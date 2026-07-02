package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/mora1n/nwall/internal/store"
)

func TestDaemonHealthStatusReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nwall.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "nwall.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{SocketPath: socketPath, DBPath: dbPath})
	}()
	client := unixHTTPClient(socketPath)
	waitForDaemon(t, client)
	var health struct {
		OK bool `json:"ok"`
	}
	getJSON(t, client, "/v1/health", &health)
	if !health.OK {
		t.Fatalf("health ok=false")
	}
	var status Status
	getJSON(t, client, "/v1/status", &status)
	if !status.OK {
		t.Fatalf("status not ok: %+v", status)
	}
	if status.Components["protect"].State != "disabled" {
		t.Fatalf("protect should be disabled by default: %+v", status.Components["protect"])
	}
	req, err := http.NewRequest(http.MethodPost, "http://nwall/v1/reload", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reload status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("daemon returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestSnapshotReconcilesProtectDisabledFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nwall.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:       Config{DBPath: dbPath},
		startedAt: nowISO(),
		components: map[string]ComponentStatus{
			"protect": {
				State:     "running",
				Message:   "规则已应用",
				UpdatedAt: nowISO(),
			},
		},
	}
	status, err := s.snapshotWithConfig()
	if err != nil {
		t.Fatal(err)
	}
	protect := status.Components["protect"]
	if protect.State != "disabled" || protect.Message != "protect.enabled=false" {
		t.Fatalf("protect status should follow DB disabled state: %+v", protect)
	}
	if !status.OK {
		t.Fatalf("disabled protect should not mark status unhealthy: %+v", status)
	}
}

func unixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func waitForDaemon(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, "http://nwall/v1/health", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready")
}

func getJSON(t *testing.T, client *http.Client, path string, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://nwall"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
