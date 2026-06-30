// Package daemon runs nwall's long-lived local control daemon.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/dpi"
	"github.com/mora1n/nwall/internal/lease"
	"github.com/mora1n/nwall/internal/mask"
	"github.com/mora1n/nwall/internal/protect"
	"github.com/mora1n/nwall/internal/store"
)

const (
	// DefaultSocketPath is the local daemon Unix socket path.
	DefaultSocketPath = "/run/nwall/nwall.sock"
	reconcileEvery    = time.Minute
)

// Config controls daemon runtime paths.
type Config struct {
	SocketPath string
	DBPath     string
}

// ComponentStatus is the user-visible state of one daemon-managed component.
type ComponentStatus struct {
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

// Status is returned by GET /v1/status.
type Status struct {
	OK         bool                       `json:"ok"`
	StartedAt  string                     `json:"started_at"`
	ReloadedAt string                     `json:"reloaded_at,omitempty"`
	Components map[string]ComponentStatus `json:"components"`
}

type Server struct {
	cfg       Config
	startedAt string

	mu          sync.Mutex
	reloadedAt  string
	components  map[string]ComponentStatus
	cancelRun   context.CancelFunc
	componentWG sync.WaitGroup
}

// Run starts the daemon and serves until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.SocketPath) == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		cfg.DBPath = store.DefaultPath
	}
	s := &Server{
		cfg:        cfg,
		startedAt:  nowISO(),
		components: map[string]ComponentStatus{},
	}
	if err := s.reload(); err != nil {
		return err
	}
	ln, err := listenSocket(cfg.SocketPath)
	if err != nil {
		s.stopComponents()
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(cfg.SocketPath)
		s.stopComponents()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/reload", s.handleReload)
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func (s *Server) reload() error {
	s.stopComponents()
	db, err := store.Open(s.cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	cfg, err := db.LoadConfig()
	if err != nil {
		return err
	}
	downmaskCfg, err := db.LoadDownmaskConfig()
	if err != nil {
		return err
	}
	policy, err := db.LoadDownmaskPolicy()
	if err != nil {
		return err
	}
	s.resetComponents()
	if cfg.Protect.Enabled {
		if err := protect.ApplyWithDBPath(cfg, true, 0, s.cfg.DBPath); err != nil {
			s.setComponent("protect", "error", "", err)
			return err
		}
		s.setComponent("protect", "running", "规则已应用", nil)
	} else {
		s.setComponent("protect", "disabled", "protect.enabled=false", nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelRun = cancel
	s.startDPI(ctx, cfg)
	s.startLeaseAgent(ctx, cfg)
	s.startLeaseTrigger(ctx, cfg)
	s.startDownmaskServer(ctx, downmaskCfg)
	s.startDownmaskRunner(ctx, policy)
	s.mu.Lock()
	s.reloadedAt = nowISO()
	s.mu.Unlock()
	return nil
}

func (s *Server) stopComponents() {
	if s.cancelRun != nil {
		s.cancelRun()
		s.componentWG.Wait()
		s.cancelRun = nil
	}
}

func (s *Server) resetComponents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.components = map[string]ComponentStatus{}
}

func (s *Server) startDPI(ctx context.Context, cfg conf.Config) {
	if !cfg.Protect.Enabled {
		s.setComponent("dpi", "disabled", "protect.enabled=false", nil)
		return
	}
	if !cfg.Protect.BlockHTTP && !cfg.Protect.BlockTLS && !cfg.Protect.BlockSOCKS {
		s.setComponent("dpi", "disabled", "未启用协议封锁", nil)
		return
	}
	s.setComponent("dpi", "running", "", nil)
	s.goComponent("dpi", func() error {
		return dpi.Run(ctx, cfg.Protect)
	})
}

func (s *Server) startLeaseAgent(ctx context.Context, cfg conf.Config) {
	if strings.TrimSpace(cfg.Lease.LeaseKey) == "" || len(cfg.Lease.Routes) == 0 {
		s.setComponent("lease_agent", "disabled", "未配置 lease key 或 route", nil)
		return
	}
	db, err := store.Open(s.cfg.DBPath)
	if err != nil {
		s.setComponent("lease_agent", "error", "", err)
		return
	}
	agent, err := lease.NewAgentWithStore(cfg, db)
	if err != nil {
		_ = db.Close()
		s.setComponent("lease_agent", "error", "", err)
		return
	}
	s.setComponent("lease_agent", "running", "", nil)
	s.goComponent("lease_agent", func() error {
		defer db.Close()
		return lease.RunAgentServer(ctx, cfg, agent)
	})
}

func (s *Server) startLeaseTrigger(ctx context.Context, cfg conf.Config) {
	if strings.TrimSpace(cfg.Lease.LeaseKey) == "" || len(cfg.LeaseTrigger.Routes) == 0 {
		s.setComponent("lease_trigger", "disabled", "未配置 lease key 或 trigger route", nil)
		return
	}
	trigger, err := lease.NewTrigger(cfg)
	if err != nil {
		s.setComponent("lease_trigger", "error", "", err)
		return
	}
	s.setComponent("lease_trigger", "running", "", nil)
	s.goComponent("lease_trigger", func() error {
		return lease.RunTriggerServer(ctx, cfg, trigger)
	})
}

func (s *Server) startDownmaskServer(ctx context.Context, cfg store.DownmaskConfig) {
	if strings.TrimSpace(cfg.Token) == "" || (strings.TrimSpace(cfg.TCPAddr) == "" && strings.TrimSpace(cfg.UDPAddr) == "") {
		s.setComponent("downmask_server", "disabled", "未配置 token 或监听地址", nil)
		return
	}
	db, err := store.Open(s.cfg.DBPath)
	if err != nil {
		s.setComponent("downmask_server", "error", "", err)
		return
	}
	s.setComponent("downmask_server", "running", "", nil)
	s.goComponent("downmask_server", func() error {
		defer db.Close()
		return mask.RunServerFromDB(ctx, db)
	})
}

func (s *Server) startDownmaskRunner(ctx context.Context, policy store.DownmaskPolicy) {
	if policy.PullMode != "ab" {
		s.setComponent("downmask_runner", "disabled", "pull_mode="+policy.PullMode, nil)
		return
	}
	s.setComponent("downmask_runner", "running", "", nil)
	s.goComponent("downmask_runner", func() error {
		ticker := time.NewTicker(reconcileEvery)
		defer ticker.Stop()
		s.runReconcileOnce()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				s.runReconcileOnce()
			}
		}
	})
}

func (s *Server) runReconcileOnce() {
	db, err := store.Open(s.cfg.DBPath)
	if err != nil {
		s.setComponent("downmask_runner", "error", "", err)
		return
	}
	defer db.Close()
	result, err := mask.Reconcile(db)
	msg := result.Action
	if result.Reason != "" {
		msg += ": " + result.Reason
	}
	s.setComponent("downmask_runner", "running", msg, err)
}

func (s *Server) goComponent(name string, fn func() error) {
	s.componentWG.Add(1)
	go func() {
		defer s.componentWG.Done()
		if err := fn(); err != nil {
			s.setComponent(name, "error", "", err)
			return
		}
		s.setComponent(name, "stopped", "", nil)
	}()
}

func (s *Server) setComponent(name, state, message string, err error) {
	status := ComponentStatus{
		State:     state,
		Message:   message,
		UpdatedAt: nowISO(),
	}
	if err != nil {
		status.Error = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.components[name] = status
}

func (s *Server) snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	components := make(map[string]ComponentStatus, len(s.components))
	ok := true
	for k, v := range s.components {
		components[k] = v
		if v.State == "error" {
			ok = false
		}
	}
	return Status{
		OK:         ok,
		StartedAt:  s.startedAt,
		ReloadedAt: s.reloadedAt,
		Components: components,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.snapshot())
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.snapshot())
}

func listenSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
