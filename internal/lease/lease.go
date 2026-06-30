// Package lease implements nwall's TCP-only temporary lease protocol.
package lease

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/nft"
	"github.com/mora1n/nwall/internal/store"
)

const (
	protocolVersion = "1"
	nonceScopeTCP   = "lease_tcp"
)

// Response 是 TCP 租约协议的响应。
type Response struct {
	OK         bool   `json:"ok"`
	Label      string `json:"label,omitempty"`
	ObservedIP string `json:"observed_ip,omitempty"`
	LeaseCIDR  string `json:"lease_cidr,omitempty"`
	IdleTTL    string `json:"idle_ttl,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Request 是 TCP 租约协议的一次请求。
type Request struct {
	Version   string `json:"version"`
	Label     string `json:"label"`
	SourceIP  string `json:"source_ip"`
	Mask      string `json:"mask,omitempty"`
	IdleTTL   string `json:"idle_ttl,omitempty"`
	TS        int64  `json:"ts"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// SendOptions 描述一次 TCP 租约发送。
type SendOptions struct {
	Target   string
	Label    string
	SourceIP string
	Mask     string
	IdleTTL  string
	Key      string
}

type sendFunc func(context.Context, SendOptions) (Response, error)

// Keygen 返回 hex 编码的 32 字节随机 key。
func Keygen() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// RunAgent starts the install-side TCP lease agent.
func RunAgent(ctx context.Context, cfg conf.Config) error {
	agent, err := NewAgent(cfg)
	if err != nil {
		return err
	}
	return RunAgentServer(ctx, cfg, agent)
}

// RunTrigger starts the public token trigger that sends TCP lease messages.
func RunTrigger(ctx context.Context, cfg conf.Config) error {
	trigger, err := NewTrigger(cfg)
	if err != nil {
		return err
	}
	return RunTriggerServer(ctx, cfg, trigger)
}

// RunTriggerServer runs a preconfigured HTTP trigger.
func RunTriggerServer(ctx context.Context, cfg conf.Config, trigger *Trigger) error {
	httpSrv := &http.Server{
		Addr:              net.JoinHostPort(cfg.LeaseTrigger.ListenHost, fmt.Sprintf("%d", cfg.LeaseTrigger.ListenPort)),
		Handler:           trigger,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	err := httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// RunAgentServer runs a preconfigured TCP lease agent.
func RunAgentServer(ctx context.Context, cfg conf.Config, agent *Agent) error {
	addr := net.JoinHostPort(cfg.Lease.ListenHost, fmt.Sprintf("%d", cfg.Lease.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			agent.ServeConn(conn)
		}()
	}
}

// Agent 是安装机侧 TCP 租约处理器。
type Agent struct {
	cfg          conf.Lease
	routes       map[string]conf.Route
	trustedRelay []netip.Prefix
	nonces       *nonceStore
	nonceDB      *store.DB
	addLease     func(netip.Prefix, string) error
	now          func() time.Time
}

// NewAgent constructs an install-side TCP lease agent.
func NewAgent(cfg conf.Config) (*Agent, error) {
	if strings.TrimSpace(cfg.Lease.LeaseKey) == "" {
		return nil, errors.New("lease.lease_key 不能为空")
	}
	routes := map[string]conf.Route{}
	for _, r := range cfg.Lease.Routes {
		route := r
		if route.IdleTTL == "" {
			route.IdleTTL = cfg.Lease.IdleTTL
		}
		if route.IPv4PrefixLen == 0 {
			route.IPv4PrefixLen = 24
		}
		if route.IPv6PrefixLen == 0 {
			route.IPv6PrefixLen = 128
		}
		routes[route.Label] = route
	}
	if len(routes) == 0 {
		return nil, errors.New("lease.routes 不能为空")
	}
	trustedRelay, err := parsePrefixes(cfg.Lease.TrustedRelayCIDRs)
	if err != nil {
		return nil, err
	}
	window := time.Duration(cfg.Lease.TSWindowSec) * time.Second
	return &Agent{
		cfg:          cfg.Lease,
		routes:       routes,
		trustedRelay: trustedRelay,
		nonces:       newNonceStore(window),
		addLease:     nft.AddLeasePrefix,
		now:          time.Now,
	}, nil
}

// Trigger 是中转机侧公网 token 触发器。
type Trigger struct {
	cfg          conf.Lease
	routes       map[string]conf.TriggerRoute
	trustedProxy []netip.Prefix
	sendLease    sendFunc
}

// NewTrigger constructs a public token trigger.
func NewTrigger(cfg conf.Config) (*Trigger, error) {
	if strings.TrimSpace(cfg.Lease.LeaseKey) == "" {
		return nil, errors.New("lease.lease_key 不能为空")
	}
	routes := map[string]conf.TriggerRoute{}
	for _, r := range cfg.LeaseTrigger.Routes {
		route := r
		if route.IdleTTL == "" {
			route.IdleTTL = cfg.Lease.IdleTTL
		}
		if route.IPv4PrefixLen == 0 {
			route.IPv4PrefixLen = 24
		}
		if route.IPv6PrefixLen == 0 {
			route.IPv6PrefixLen = 128
		}
		routes[route.Token] = route
	}
	if len(routes) == 0 {
		return nil, errors.New("lease_trigger.routes 不能为空")
	}
	trustedProxy, err := parsePrefixes(cfg.LeaseTrigger.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	return &Trigger{
		cfg:          cfg.Lease,
		routes:       routes,
		trustedProxy: trustedProxy,
		sendLease:    Send,
	}, nil
}

// ServeHTTP handles GET /<token> and asks the TCP agent to create a lease.
func (t *Trigger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, status, err := t.handleHTTP(r)
	if err != nil {
		resp = Response{OK: false, Error: err.Error()}
	}
	writeJSON(w, status, resp)
}

func (t *Trigger) handleHTTP(r *http.Request) (Response, int, error) {
	if r.Method != http.MethodGet {
		return Response{}, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed: %s", r.Method)
	}
	token, ok := tokenFromPath(r.URL.Path)
	if !ok {
		return Response{}, http.StatusNotFound, errors.New("route not found")
	}
	route, ok := t.routes[token]
	if !ok {
		return Response{}, http.StatusNotFound, fmt.Errorf("route not found: %s", token)
	}
	sourceIP, err := t.sourceIP(r)
	if err != nil {
		return Response{}, http.StatusBadRequest, err
	}
	mask := strings.TrimSpace(r.URL.Query().Get("mask"))
	if mask != "" {
		if _, err := parseLeaseMask(mask); err != nil {
			return Response{}, http.StatusBadRequest, err
		}
	}
	sourceAddr, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return Response{}, http.StatusBadRequest, fmt.Errorf("来源 IP 无效: %w", err)
	}
	if mask == "" {
		if sourceAddr.Is4() && route.IPv4PrefixLen != 0 {
			mask = strconv.Itoa(route.IPv4PrefixLen)
		}
		if sourceAddr.Is6() && route.IPv6PrefixLen != 0 {
			mask = strconv.Itoa(route.IPv6PrefixLen)
		}
	}
	sendCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := t.sendLease(sendCtx, SendOptions{
		Target:   route.Target,
		Label:    route.Label,
		SourceIP: sourceIP,
		Mask:     mask,
		IdleTTL:  route.IdleTTL,
		Key:      t.cfg.LeaseKey,
	})
	if err != nil {
		return resp, http.StatusBadGateway, err
	}
	return resp, http.StatusOK, nil
}

func (t *Trigger) sourceIP(r *http.Request) (string, error) {
	peer, err := addrFromRemoteString(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	if isTrusted(peer.String(), t.trustedProxy) {
		if ip := firstHeaderIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip, nil
		}
		if ip := firstHeaderIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip, nil
		}
	}
	return peer.String(), nil
}

// NewAgentWithStore constructs a TCP lease agent backed by a persistent nonce store.
func NewAgentWithStore(cfg conf.Config, db *store.DB) (*Agent, error) {
	agent, err := NewAgent(cfg)
	if err != nil {
		return nil, err
	}
	agent.nonceDB = db
	return agent, nil
}

// ServeConn handles one TCP lease request and writes one JSON response.
func (a *Agent) ServeConn(conn net.Conn) {
	resp, err := a.handle(conn.RemoteAddr(), json.NewDecoder(conn))
	if err != nil {
		resp = Response{OK: false, Error: err.Error()}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (a *Agent) handle(remote net.Addr, dec *json.Decoder) (Response, error) {
	peer, err := addrFromNetAddr(remote)
	if err != nil {
		return Response{}, err
	}
	if len(a.trustedRelay) > 0 && !isTrusted(peer.String(), a.trustedRelay) {
		return Response{}, fmt.Errorf("relay peer not trusted: %s", peer)
	}
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Response{}, fmt.Errorf("解析 TCP 租约请求失败: %w", err)
	}
	if err := a.verifyRequest(req); err != nil {
		return Response{}, err
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = firstRouteLabel(a.routes)
	}
	route, ok := a.routes[label]
	if !ok {
		return Response{}, fmt.Errorf("route not found: %s", label)
	}
	observedAddr, err := netip.ParseAddr(strings.TrimSpace(req.SourceIP))
	if err != nil {
		return Response{}, fmt.Errorf("来源 IP 无效: %w", err)
	}
	if err := ensureAllowed(observedAddr, route.IPAllowCIDRs); err != nil {
		return Response{}, err
	}
	if req.IdleTTL != "" {
		if err := validateLeaseTTL(req.IdleTTL); err != nil {
			return Response{}, fmt.Errorf("idle_ttl 无效: %w", err)
		}
		route.IdleTTL = req.IdleTTL
	}
	if route.IdleTTL == "" {
		route.IdleTTL = a.cfg.IdleTTL
	}
	prefix, err := leasePrefix(req.SourceIP, route, req.Mask)
	if err != nil {
		return Response{}, err
	}
	if err := a.addLease(prefix, route.IdleTTL); err != nil {
		return Response{}, err
	}
	return Response{OK: true, Label: route.Label, ObservedIP: observedAddr.String(), LeaseCIDR: prefix.String(), IdleTTL: route.IdleTTL}, nil
}

func (a *Agent) verifyRequest(req Request) error {
	if req.Version != protocolVersion {
		return fmt.Errorf("unsupported lease protocol version: %q", req.Version)
	}
	if strings.TrimSpace(req.SourceIP) == "" || strings.TrimSpace(req.Nonce) == "" || strings.TrimSpace(req.Signature) == "" {
		return errors.New("missing TCP lease auth fields")
	}
	window := time.Duration(a.cfg.TSWindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	parsed := time.Unix(req.TS, 0)
	if delta := a.now().Sub(parsed); delta > window || delta < -window {
		return errors.New("timestamp outside window")
	}
	if !hmac.Equal([]byte(req.Signature), []byte(signRequest(a.cfg.LeaseKey, req))) {
		return errors.New("invalid signature")
	}
	expires := a.now().Add(window)
	if a.nonceDB != nil {
		ok, err := a.nonceDB.RecordNonce(nonceScopeTCP, req.Nonce, expires)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("replayed nonce")
		}
		return nil
	}
	if !a.nonces.Seen(req.Nonce, a.now(), expires) {
		return errors.New("replayed nonce")
	}
	return nil
}

// Send sends one TCP lease request and returns the peer response.
func Send(ctx context.Context, opts SendOptions) (Response, error) {
	if strings.TrimSpace(opts.Target) == "" {
		return Response{}, errors.New("--target 必填")
	}
	if strings.TrimSpace(opts.Key) == "" {
		return Response{}, errors.New("lease key 不能为空")
	}
	req, err := NewSignedRequest(opts, time.Now())
	if err != nil {
		return Response{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", opts.Target)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// NewSignedRequest builds a signed TCP lease request.
func NewSignedRequest(opts SendOptions, now time.Time) (Request, error) {
	if strings.TrimSpace(opts.SourceIP) == "" {
		return Request{}, errors.New("--source-ip 必填")
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(opts.SourceIP)); err != nil {
		return Request{}, fmt.Errorf("来源 IP 无效: %w", err)
	}
	if opts.IdleTTL != "" {
		if err := validateLeaseTTL(opts.IdleTTL); err != nil {
			return Request{}, fmt.Errorf("idle_ttl 无效: %w", err)
		}
	}
	if strings.TrimSpace(opts.Mask) != "" {
		if _, err := parseLeaseMask(opts.Mask); err != nil {
			return Request{}, err
		}
	}
	nonce, err := Keygen()
	if err != nil {
		return Request{}, err
	}
	req := Request{
		Version:  protocolVersion,
		Label:    strings.TrimSpace(opts.Label),
		SourceIP: strings.TrimSpace(opts.SourceIP),
		Mask:     strings.TrimSpace(opts.Mask),
		IdleTTL:  strings.TrimSpace(opts.IdleTTL),
		TS:       now.Unix(),
		Nonce:    nonce,
	}
	req.Signature = signRequest(opts.Key, req)
	return req, nil
}

func signRequest(key string, req Request) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(signatureBase(req)))
	return hex.EncodeToString(mac.Sum(nil))
}

func signatureBase(req Request) string {
	return strings.Join([]string{
		"v1",
		req.Label,
		req.SourceIP,
		req.Mask,
		req.IdleTTL,
		strconv.FormatInt(req.TS, 10),
		req.Nonce,
	}, "|")
}

func leasePrefix(observedIP string, route conf.Route, mask string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(observedIP))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("来源 IP 无效: %w", err)
	}
	bits := route.IPv6PrefixLen
	if addr.Is4() {
		bits = route.IPv4PrefixLen
	}
	if bits == 0 {
		if addr.Is4() {
			bits = 24
		} else {
			bits = 128
		}
	}
	if strings.TrimSpace(mask) != "" {
		parsed, err := parseLeaseMask(mask)
		if err != nil {
			return netip.Prefix{}, err
		}
		bits = parsed
	}
	if addr.Is4() {
		if bits < 24 || bits > 32 {
			return netip.Prefix{}, fmt.Errorf("IPv4 lease mask 只支持 24-32，当前=%d", bits)
		}
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}
	if bits != 128 {
		return netip.Prefix{}, fmt.Errorf("IPv6 lease mask 只支持 128，当前=%d", bits)
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func parseLeaseMask(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "/")
	bits, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("无效 lease mask: %q", raw)
	}
	return bits, nil
}

func validateLeaseTTL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("不能为空")
	}
	if _, err := time.ParseDuration(raw); err == nil {
		return nil
	}
	if !strings.HasSuffix(raw, "d") {
		return fmt.Errorf("必须是 Go duration 或整数天，例如 10m、1h、3d")
	}
	days, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
	if err != nil || days <= 0 {
		return fmt.Errorf("无效天数: %s", raw)
	}
	return nil
}

func ensureAllowed(addr netip.Addr, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("source ip not allowed: %s", addr)
}

func addrFromNetAddr(raw net.Addr) (netip.Addr, error) {
	if raw == nil {
		return netip.Addr{}, errors.New("remote addr 为空")
	}
	host, _, err := net.SplitHostPort(raw.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote addr 无效: %w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote addr 不是 IP: %w", err)
	}
	return addr, nil
}

func addrFromRemoteString(raw string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote addr 无效: %w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote addr 不是 IP: %w", err)
	}
	return addr, nil
}

func tokenFromPath(path string) (string, bool) {
	if path == "" || path == "/" || !strings.HasPrefix(path, "/") {
		return "", false
	}
	token := strings.TrimPrefix(path, "/")
	if token == "" || strings.Contains(token, "/") {
		return "", false
	}
	return token, true
}

func firstHeaderIP(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err == nil {
			return addr.String()
		}
	}
	return ""
}

func isTrusted(raw string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePrefixes(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, item := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("无效 CIDR: %s", item)
		}
		out = append(out, p)
	}
	return out, nil
}

func firstRouteLabel(routes map[string]conf.Route) string {
	for label := range routes {
		return label
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type nonceStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]time.Time
}

func newNonceStore(ttl time.Duration) *nonceStore {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &nonceStore{ttl: ttl, entries: map[string]time.Time{}}
}

// Seen records nonce when it is new; returns false for replay.
func (s *nonceStore) Seen(nonce string, now time.Time, expires time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, exp := range s.entries {
		if now.After(exp) {
			delete(s.entries, key)
		}
	}
	if _, ok := s.entries[nonce]; ok {
		return false
	}
	s.entries[nonce] = expires
	return true
}
