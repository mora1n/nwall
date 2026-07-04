package mask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mora1n/nwall/internal/store"
)

func TestHeaderAndSeed(t *testing.T) {
	t.Run("request_header_roundtrip", func(t *testing.T) {
		hdr := requestHeader{
			Magic:       protoMagic,
			Version:     protoVersion,
			TokenSHA256: tokenDigest("hello"),
			WantedBytes: 12345,
			SpeedLimit:  6789,
		}
		buf, err := hdr.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(buf) != headerSize {
			t.Fatalf("header size = %d, want %d", len(buf), headerSize)
		}
		var got requestHeader
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != hdr {
			t.Fatalf("roundtrip mismatch: %+v vs %+v", got, hdr)
		}
	})

	t.Run("seed_generate", func(t *testing.T) {
		t.Run("default_size_is_1gb", func(t *testing.T) {
			fs := flag.NewFlagSet("seed", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var path string
			var size int64
			fs.StringVar(&path, "path", "/var/lib/nwall/downmask/seed.bin", "种子文件路径，默认 /var/lib/nwall/downmask/seed.bin")
			fs.Int64Var(&size, "size", 1024*1024*1024, "种子文件字节大小；默认 1GB，推荐 256MB-4GB")
			if err := fs.Parse(nil); err != nil {
				t.Fatalf("parse default seed flags: %v", err)
			}
			if size != 1024*1024*1024 {
				t.Fatalf("default seed size = %d, want %d", size, int64(1024*1024*1024))
			}
		})

		testCases := []struct {
			name     string
			sizeArg  string
			wantSize int64
		}{
			{name: "raw_bytes", sizeArg: "65536", wantSize: 65536},
			{name: "unit_bytes_from_shell", sizeArg: "268435456", wantSize: 268435456},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("NWALL_DB", filepath.Join(dir, "nwall.db"))
				path := filepath.Join(dir, "seed.bin")
				if err := runSeed([]string{"--path", path, "--size", tc.sizeArg}); err != nil {
					t.Fatalf("runSeed: %v", err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("stat: %v", err)
				}
				if info.Size() != tc.wantSize {
					t.Fatalf("size = %d, want %d", info.Size(), tc.wantSize)
				}
				if tc.wantSize <= 65536 {
					data, _ := os.ReadFile(path)
					if bytes.Equal(data, make([]byte, len(data))) {
						t.Fatalf("seed file is all zeros")
					}
				}
				db, err := store.Open(filepath.Join(dir, "nwall.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				rows, err := db.SQL().Query(`SELECT COUNT(*) FROM downmask_seed_chunks`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				if !rows.Next() {
					t.Fatal("missing seed chunk count")
				}
				var chunks int
				if err := rows.Scan(&chunks); err != nil {
					t.Fatal(err)
				}
				if chunks != 0 {
					t.Fatalf("runSeed must not write DB seed chunks, got %d", chunks)
				}
			})
		}
	})
}

func TestHelpExplainsToken(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	got := buf.String()
	for _, want := range []string{
		"--token <downmask-key>",
		"<downmask-key> 是下行伪装共享密钥",
		"openssl rand -hex 16",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output missing %q:\n%s", want, got)
		}
	}
}

func TestPullIntegration(t *testing.T) {
	testCases := []struct {
		name        string
		protocol    string
		token       string
		serverToken string
		wanted      uint64
		wantActual  uint64
	}{
		{
			name:        "tcp_success",
			protocol:    "tcp",
			token:       "test-token",
			serverToken: "test-token",
			wanted:      131072,
			wantActual:  131072,
		},
		{
			name:        "tcp_bad_token",
			protocol:    "tcp",
			token:       "wrong-token",
			serverToken: "server-token",
			wanted:      1024,
			wantActual:  0,
		},
		{
			name:        "udp_exact_bytes",
			protocol:    "udp",
			token:       "udp-token",
			serverToken: "udp-token",
			wanted:      1500,
			wantActual:  1500,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
			port, cleanup := startPullTestServer(t, tc.protocol, tc.serverToken, newTestSeed(1024*1024), status)
			defer cleanup()

			stdout, restore := captureStdout(t)
			defer restore()

			wantedArg := strconv.FormatUint(tc.wanted, 10)
			if tc.wanted == 1500 {
				wantedArg = "1.5KB"
			}
			args := []string{
				"--protocol", tc.protocol,
				"--remote-host", "127.0.0.1",
				"--remote-port", strconv.Itoa(port),
				"--token", tc.token,
				"--wanted-bytes", wantedArg,
				"--timeout", "3",
			}
			if err := runPull(args); err != nil {
				t.Fatalf("runPull: %v", err)
			}

			var result pullResult
			if err := json.Unmarshal([]byte(strings.TrimSpace(stdout())), &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if result.Protocol != tc.protocol {
				t.Fatalf("protocol = %s, want %s", result.Protocol, tc.protocol)
			}
			if result.ActualBytes != tc.wantActual {
				t.Fatalf("actual_bytes = %d, want %d", result.ActualBytes, tc.wantActual)
			}
		})
	}
}

func TestServeValidationAndHelpers(t *testing.T) {
	t.Run("helper", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload int
			wantErr string
		}{
			{name: "min_ok", payload: udpMinPayload},
			{name: "default_ok", payload: udpDefaultPayload},
			{name: "max_ok", payload: udpMaxPayload},
			{name: "too_small", payload: udpMinPayload - 1, wantErr: "udp payload 必须位于"},
			{name: "too_large", payload: udpMaxPayload + 1, wantErr: "udp payload 必须位于"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateUDPPayloadBytes(tc.payload)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("validateUDPPayloadBytes(%d): %v", tc.payload, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("validateUDPPayloadBytes(%d) = %v, want substring %q", tc.payload, err, tc.wantErr)
				}
			})
		}
	})

	t.Run("load_seed_from_file_without_reading_whole_file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "seed.bin")
		data := newTestSeed(4096)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}

		src, closeFn, err := loadOrGenSeed(path)
		if err != nil {
			t.Fatalf("loadOrGenSeed: %v", err)
		}
		if closeFn == nil {
			t.Fatal("expected close function for file-backed seed")
		}
		defer closeFn()

		fileSrc, ok := src.(*fileSeedSource)
		if !ok {
			t.Fatalf("seed source type = %T, want *fileSeedSource", src)
		}
		if fileSrc.size != int64(len(data)) {
			t.Fatalf("file seed size = %d, want %d", fileSrc.size, len(data))
		}

		buf := make([]byte, 6000)
		if err := src.ReadRandom(buf); err != nil {
			t.Fatalf("ReadRandom: %v", err)
		}
		if bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatal("ReadRandom returned all zeros")
		}
	})
}

func TestRunServePayloadValidation(t *testing.T) {
	t.Run("rejects_invalid_payload", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload int
		}{
			{name: "too_small", payload: udpMinPayload - 1},
			{name: "too_large", payload: udpMaxPayload + 1},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := runServe([]string{
					"--udp-addr", "127.0.0.1:0",
					"--token", "test-token",
					"--udp-payload-bytes", strconv.Itoa(tc.payload),
				})
				if err == nil || !strings.Contains(err.Error(), "--udp-payload-bytes") {
					t.Fatalf("runServe invalid payload error = %v, want udp-payload-bytes error", err)
				}
			})
		}
	})

	t.Run("accepts_valid_payload", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- runServeContext(ctx, serveOptions{
				UDPAddr:    "127.0.0.1:0",
				Token:      "test-token",
				SeedFile:   writeTestSeedFile(t, t.TempDir()),
				UDPPayload: udpDefaultPayload,
			}, nil)
		}()

		time.Sleep(150 * time.Millisecond)
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("runServe valid payload: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("runServe did not stop after SIGTERM")
		}
	})

	t.Run("local_addr_helpers", func(t *testing.T) {
		addr, err := localTCPAddr(net.ParseIP("127.0.0.2"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80})
		if err != nil {
			t.Fatalf("localTCPAddr: %v", err)
		}
		if got := addr.IP.String(); got != "127.0.0.2" {
			t.Fatalf("addr.IP = %s", got)
		}

		_, err = localUDPAddr(net.ParseIP("127.0.0.2"), &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53})
		if err == nil || !strings.Contains(err.Error(), "地址族不匹配") {
			t.Fatalf("expected family mismatch, got %v", err)
		}
	})

	t.Run("write_status_snapshot", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "status.json")
		status := &serveStatus{
			tcpListening:   true,
			udpListening:   true,
			bindIP:         "127.0.0.1",
			tcpPort:        1001,
			udpPort:        1002,
			totalBytesSent: 4096,
			activeSessions: 2,
			udpSessions:    make(map[udpSessionKey]struct{}),
		}
		writeStatusFile(path, status)

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read status file: %v", err)
		}
		var snap serveStatusJSON
		if err := json.Unmarshal(data, &snap); err != nil {
			t.Fatalf("unmarshal status: %v", err)
		}
		if !snap.TCPListening || !snap.UDPListening {
			t.Fatalf("unexpected listening flags: %+v", snap)
		}
		if snap.TotalBytesSent != 4096 || snap.ActiveSessions != 2 {
			t.Fatalf("unexpected counters: %+v", snap)
		}
	})

	t.Run("udp_session_dedup", func(t *testing.T) {
		status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
		var sessionID [udpSessionLen]byte
		copy(sessionID[:], []byte("dedup-session-01"))
		key := udpSessionKey{Addr: "127.0.0.1:12345", SessionID: sessionID}

		if !status.tryStartUDPSession(key) {
			t.Fatalf("first start should succeed")
		}
		if status.tryStartUDPSession(key) {
			t.Fatalf("duplicate start should be rejected")
		}
		status.finishUDPSession(key)
		if !status.tryStartUDPSession(key) {
			t.Fatalf("start after finish should succeed")
		}
	})
}

func TestRandomSeedReader(t *testing.T) {
	t.Run("random_slice_sizes", func(t *testing.T) {
		reader, err := newSeedReader(newTestSeed(64))
		if err != nil {
			t.Fatalf("newSeedReader: %v", err)
		}
		for _, size := range []int{0, 8, 32, 64, 96} {
			buf, err := reader.randomSlice(size)
			if err != nil {
				t.Fatalf("randomSlice(%d): %v", size, err)
			}
			if len(buf) != size {
				t.Fatalf("len(randomSlice(%d)) = %d", size, len(buf))
			}
		}
	})

	t.Run("empty_seed_rejected", func(t *testing.T) {
		if _, err := newSeedReader(nil); err == nil {
			t.Fatal("expected empty seed error")
		}
	})
}

func TestUDPFlow(t *testing.T) {
	testCases := []struct {
		name             string
		wanted           uint64
		payload          int
		wantBytes        int
		wantPackets      int
		wantMaxPacketLen int
	}{
		{
			name:             "exact_remaining_default_payload",
			wanted:           1500,
			payload:          udpDefaultPayload,
			wantBytes:        1500,
			wantPackets:      2,
			wantMaxPacketLen: udpDefaultPayload,
		},
		{
			name:             "custom_payload_respected",
			wanted:           2000,
			payload:          600,
			wantBytes:        2000,
			wantPackets:      4,
			wantMaxPacketLen: 600,
		},
		{
			name:             "invalid_payload_skips_send",
			wanted:           1024,
			payload:          udpMinPayload - 1,
			wantBytes:        0,
			wantPackets:      0,
			wantMaxPacketLen: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pc := newRecordingPacketConn()
			status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
			src, err := newSeedReader(bytes.Repeat([]byte("a"), 4096))
			if err != nil {
				t.Fatalf("newSeedReader: %v", err)
			}
			var sessionID [udpSessionLen]byte
			copy(sessionID[:], []byte("udp-flow-check01"))
			key := udpSessionKey{Addr: "peer", SessionID: sessionID}
			if !status.tryStartUDPSession(key) {
				t.Fatalf("failed to register UDP session")
			}

			handleUDPSession(pc, dummyAddr("peer"), sessionID, tc.wanted, 0, src, tc.payload, key, status)

			totalPayload, maxPacketLen := pc.payloadStats()
			if totalPayload != tc.wantBytes {
				t.Fatalf("payload = %d, want %d", totalPayload, tc.wantBytes)
			}
			if len(pc.packets) != tc.wantPackets {
				t.Fatalf("packets = %d, want %d", len(pc.packets), tc.wantPackets)
			}
			if maxPacketLen != tc.wantMaxPacketLen {
				t.Fatalf("max packet len = %d, want %d", maxPacketLen, tc.wantMaxPacketLen)
			}
		})
	}
}

func TestRateLimiterShape(t *testing.T) {
	r := newRateLimiter(1024 * 1024)
	start := time.Now()
	for i := 0; i < 10; i++ {
		r.wait(102400)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("rate limiter too slow: %v", elapsed)
	}
}

func TestParseRateBytesPerSecond(t *testing.T) {
	testCases := []struct {
		raw  string
		want uint64
	}{
		{raw: "", want: 0},
		{raw: "4096", want: 4096},
		{raw: "4M", want: 4 * 1024 * 1024},
		{raw: "1.5M", want: 1572864},
		{raw: "32Mbps", want: 4000000},
		{raw: "2MB/s", want: 2000000},
		{raw: "10MB", want: 10_000_000},
		{raw: "1GiB", want: 1024 * 1024 * 1024},
	}
	for _, tc := range testCases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseRateBytesPerSecond(tc.raw)
			if err != nil {
				t.Fatalf("parseRateBytesPerSecond(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseRateBytesPerSecond(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseByteAmount(t *testing.T) {
	testCases := []struct {
		raw  string
		want uint64
	}{
		{raw: "0", want: 0},
		{raw: "4096", want: 4096},
		{raw: "20MB", want: 20_000_000},
		{raw: "1.5GB", want: 1_500_000_000},
		{raw: "512MiB", want: 512 * 1024 * 1024},
		{raw: "2M", want: 2 * 1024 * 1024},
	}
	for _, tc := range testCases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseByteAmount(tc.raw)
			if err != nil {
				t.Fatalf("parseByteAmount(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseByteAmount(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
	for _, raw := range []string{"", "-1MB", "abc"} {
		if _, err := parseByteAmount(raw); err == nil {
			t.Fatalf("parseByteAmount(%q) should fail", raw)
		}
	}
}

func TestDownmaskPolicyAndABPullCommandsUpdateDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nwall.db")
	t.Setenv("NWALL_DB", dbPath)
	if err := runPolicy([]string{"set", "--pull-mode", "ab", "--iface", "eth0", "--min-ratio", "1.5", "--max-ratio", "2", "--max-jitter", "0", "--min-deficit-bytes", "20MB", "--max-bytes-per-run", "500MB"}); err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	if err := runABPullSet([]string{"--protocol-mode", "parallel", "--tcp-enabled", "true", "--udp-enabled", "true", "--remote-port", "15301", "--token", "test-token", "--speed-limit", "4M", "--timeout", "30"}); err != nil {
		t.Fatalf("runABPullSet: %v", err)
	}
	if err := runABPullTargets([]string{"add", "192.0.2.20", "--weight", "2", "--udp-enabled", "false"}); err != nil {
		t.Fatalf("runABPullTargets: %v", err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy, err := db.LoadDownmaskPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.PullMode != "ab" || policy.Iface != "eth0" || policy.MinDeficitBytes != 20_000_000 || policy.MaxBytesPerRun != 500_000_000 {
		t.Fatalf("policy mismatch: %+v", policy)
	}
	cfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProtocolMode != "parallel" || !cfg.TCPEnabled || !cfg.UDPEnabled || cfg.RemotePort != 15301 {
		t.Fatalf("config mismatch: %+v", cfg)
	}
	targets, err := db.LoadDownmaskABTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "192.0.2.20" || targets[0].UDPEnabled {
		t.Fatalf("targets mismatch: %+v", targets)
	}
}

func TestReconcileSkipsBelowMinDeficit(t *testing.T) {
	db := openMaskTestDB(t)
	mustSavePolicy(t, db, store.DownmaskPolicy{
		PullMode:        "ab",
		Iface:           "eth0",
		MinRatio:        1.5,
		MaxRatio:        1.5,
		MinDeficitBytes: 1024,
	})
	withMaskHooks(t, hookConfig{
		now: func() time.Time { return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC) },
		read: func(string) (ifaceBytes, error) {
			return ifaceBytes{RX: 1000, TX: 1000}, nil
		},
		randomIntn: func(int) (int, error) { return 0, nil },
	})
	if _, err := prepareDayState(db, store.DownmaskPolicy{PullMode: "ab", Iface: "eth0", MinRatio: 1.5, MaxRatio: 1.5}, ifaceBytes{RX: 1000, TX: 1000}); err != nil {
		t.Fatalf("prepareDayState: %v", err)
	}
	readIfaceBytesFunc = func(string) (ifaceBytes, error) {
		return ifaceBytes{RX: 1100, TX: 1200}, nil
	}

	result, err := reconcileDownmask(db)
	if err != nil {
		t.Fatalf("reconcileDownmask: %v", err)
	}
	if result.Action != "skip" || result.Reason != "below_min_deficit" || result.DebtBytes != 200 {
		t.Fatalf("unexpected result: %+v", result)
	}
	state, ok, err := db.LoadDownmaskDayState()
	if err != nil || !ok {
		t.Fatalf("LoadDownmaskDayState ok=%v err=%v", ok, err)
	}
	if state.RXAccum != 100 || state.TXAccum != 200 || state.LastError != "below_min_deficit" {
		t.Fatalf("state mismatch: %+v", state)
	}
}

func TestReconcileAutoDetectsIfaceWhenEmpty(t *testing.T) {
	db := openMaskTestDB(t)
	mustSavePolicy(t, db, store.DownmaskPolicy{
		PullMode:        "ab",
		Iface:           "",
		MinRatio:        1.5,
		MaxRatio:        1.5,
		MinDeficitBytes: 1024,
	})
	readIface := ""
	withMaskHooks(t, hookConfig{
		now: func() time.Time { return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC) },
		detect: func() (string, error) {
			return "eth0", nil
		},
		read: func(iface string) (ifaceBytes, error) {
			readIface = iface
			return ifaceBytes{RX: 1000, TX: 1000}, nil
		},
	})

	result, err := reconcileDownmask(db)
	if err != nil {
		t.Fatalf("reconcileDownmask: %v", err)
	}
	if readIface != "eth0" || result.Iface != "eth0" {
		t.Fatalf("iface mismatch read=%q result=%q", readIface, result.Iface)
	}
	state, ok, err := db.LoadDownmaskDayState()
	if err != nil || !ok {
		t.Fatalf("LoadDownmaskDayState ok=%v err=%v", ok, err)
	}
	if state.Iface != "eth0" {
		t.Fatalf("state iface = %q, want eth0", state.Iface)
	}
}

func TestReconcileUsesExplicitIfaceWithoutDetect(t *testing.T) {
	db := openMaskTestDB(t)
	mustSavePolicy(t, db, store.DownmaskPolicy{
		PullMode:        "ab",
		Iface:           "eth1",
		MinRatio:        1.5,
		MaxRatio:        1.5,
		MinDeficitBytes: 1024,
	})
	readIface := ""
	withMaskHooks(t, hookConfig{
		now: func() time.Time { return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC) },
		detect: func() (string, error) {
			return "", errors.New("detector should not be called")
		},
		read: func(iface string) (ifaceBytes, error) {
			readIface = iface
			return ifaceBytes{RX: 1000, TX: 1000}, nil
		},
	})

	result, err := reconcileDownmask(db)
	if err != nil {
		t.Fatalf("reconcileDownmask: %v", err)
	}
	if readIface != "eth1" || result.Iface != "eth1" {
		t.Fatalf("iface mismatch read=%q result=%q", readIface, result.Iface)
	}
}

func TestReconcileFailsWhenIfaceAutoDetectFails(t *testing.T) {
	db := openMaskTestDB(t)
	mustSavePolicy(t, db, store.DownmaskPolicy{PullMode: "ab", MinRatio: 1.5, MaxRatio: 1.5})
	withMaskHooks(t, hookConfig{
		detect: func() (string, error) {
			return "", errors.New("no default route")
		},
	})

	_, err := reconcileDownmask(db)
	if err == nil || !strings.Contains(err.Error(), "自动探测失败") {
		t.Fatalf("error = %v, want auto detect failure", err)
	}
}

func TestReconcilePullsDebtAndRecordsState(t *testing.T) {
	db := openMaskTestDB(t)
	mustSavePolicy(t, db, store.DownmaskPolicy{
		PullMode:         "ab",
		Iface:            "eth0",
		MinRatio:         1.5,
		MaxRatio:         1.5,
		MaxJitterSeconds: 0,
		MinDeficitBytes:  100,
		MaxBytesPerRun:   500,
		TimeWindowStart:  "",
		TimeWindowEnd:    "",
	})
	mustSaveABConfig(t, db, store.DownmaskABPullConfig{
		Protocol:       "tcp",
		ProtocolMode:   "single",
		TCPEnabled:     true,
		RemotePort:     15301,
		Token:          "test-token",
		SpeedLimit:     "4M",
		TimeoutSeconds: 30,
		ParallelLimit:  1,
	})
	if err := db.UpsertDownmaskABTarget(store.DownmaskABTarget{Host: "192.0.2.20", Weight: 1, TCPEnabled: true, UDPEnabled: true}); err != nil {
		t.Fatal(err)
	}
	baseNow := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	pullCalls := 0
	withMaskHooks(t, hookConfig{
		now: func() time.Time { return baseNow },
		read: func(string) (ifaceBytes, error) {
			return ifaceBytes{RX: 1000, TX: 1000}, nil
		},
		pull: func(opts pullOptions) (uint64, error) {
			pullCalls++
			if opts.RemoteHost != "192.0.2.20" || opts.RemotePort != 15301 || opts.WantedBytes != 500 {
				t.Fatalf("pull opts mismatch: %+v", opts)
			}
			return opts.WantedBytes, nil
		},
		randomIntn: func(int) (int, error) { return 0, nil },
	})
	if _, err := prepareDayState(db, store.DownmaskPolicy{PullMode: "ab", Iface: "eth0", MinRatio: 1.5, MaxRatio: 1.5}, ifaceBytes{RX: 1000, TX: 1000}); err != nil {
		t.Fatalf("prepareDayState: %v", err)
	}
	readIfaceBytesFunc = func(string) (ifaceBytes, error) {
		return ifaceBytes{RX: 1200, TX: 2000}, nil
	}

	result, err := reconcileDownmask(db)
	if err != nil {
		t.Fatalf("reconcileDownmask: %v", err)
	}
	if pullCalls != 1 {
		t.Fatalf("pull calls = %d, want 1", pullCalls)
	}
	if result.Action != "ab" || result.PlannedBytes != 500 || result.ActualBytes != 500 || result.Reason != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	state, ok, err := db.LoadDownmaskDayState()
	if err != nil || !ok {
		t.Fatalf("LoadDownmaskDayState ok=%v err=%v", ok, err)
	}
	if state.LastAction != "ab" || state.LastActualBytes != 500 || state.LastPlannedBytes != 500 {
		t.Fatalf("state mismatch: %+v", state)
	}
}

func TestReconcileNewDayUsesHistory(t *testing.T) {
	db := openMaskTestDB(t)
	prev := 1.5
	if err := db.SaveDownmaskRatioHistory(store.DownmaskRatioHistory{
		Date:             "2026-06-29",
		TargetRatio:      prev,
		GenerationSource: "fresh_init",
		GeneratedAt:      "2026-06-29T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	policy := store.DownmaskPolicy{PullMode: "ab", Iface: "eth0", MinRatio: 1.5, MaxRatio: 1.5}
	withMaskHooks(t, hookConfig{
		now:        func() time.Time { return time.Date(2026, 6, 30, 0, 1, 0, 0, time.UTC) },
		randomIntn: func(int) (int, error) { return 0, nil },
	})
	state, err := prepareDayState(db, policy, ifaceBytes{RX: 10, TX: 20})
	if err != nil {
		t.Fatalf("prepareDayState: %v", err)
	}
	if state.PreviousTargetRatio == nil || *state.PreviousTargetRatio != prev || state.GenerationSource != "rollover_history_fallback" {
		t.Fatalf("previous history not used: %+v", state)
	}
	if state.TargetRatio != 1.5 {
		t.Fatalf("target ratio = %f, want 1.5", state.TargetRatio)
	}
}

func TestABTargetFallback(t *testing.T) {
	db := openMaskTestDB(t)
	mustSaveABConfig(t, db, store.DownmaskABPullConfig{
		Protocol:       "tcp",
		ProtocolMode:   "single",
		TCPEnabled:     true,
		RemotePort:     15301,
		Token:          "test-token",
		SpeedLimit:     "0",
		TimeoutSeconds: 30,
		ParallelLimit:  1,
	})
	for _, host := range []string{"192.0.2.10", "192.0.2.20"} {
		if err := db.UpsertDownmaskABTarget(store.DownmaskABTarget{Host: host, Weight: 1, TCPEnabled: true, UDPEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	calls := []string{}
	withMaskHooks(t, hookConfig{
		randomIntn: func(int) (int, error) { return 0, nil },
		pull: func(opts pullOptions) (uint64, error) {
			calls = append(calls, opts.RemoteHost)
			if opts.RemoteHost == "192.0.2.10" {
				return 0, errors.New("dial failed")
			}
			return 1234, nil
		},
	})
	actual, err := pullAB(db, 2048)
	if err != nil {
		t.Fatalf("pullAB: %v", err)
	}
	if actual != 1234 {
		t.Fatalf("actual = %d, want 1234", actual)
	}
	if strings.Join(calls, ",") != "192.0.2.10,192.0.2.20" {
		t.Fatalf("fallback calls = %v", calls)
	}
}

func TestStatusShowsDynamicState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nwall.db")
	t.Setenv("NWALL_DB", dbPath)
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	mustSavePolicy(t, db, store.DownmaskPolicy{PullMode: "ab", Iface: "eth0", MinRatio: 1.5, MaxRatio: 2, MinDeficitBytes: 1024})
	mustSaveABConfig(t, db, store.DownmaskABPullConfig{Protocol: "tcp", ProtocolMode: "single", TCPEnabled: true, RemotePort: 15301, SpeedLimit: "4M", TimeoutSeconds: 30, ParallelLimit: 1})
	if err := db.SaveDownmaskDayState(store.DownmaskDayState{
		Date:             "2026-06-30",
		Iface:            "eth0",
		TargetRatio:      1.5,
		RXAccum:          100,
		TXAccum:          200,
		GenerationSource: "fresh_init",
		GeneratedAt:      "2026-06-30T00:00:00Z",
		LastAction:       "skip",
		LastError:        "below_min_deficit",
		UpdatedAt:        "2026-06-30T00:01:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, restore := captureStdout(t)
	defer restore()
	if err := runStatus(nil); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
	got := stdout()
	for _, want := range []string{"pull_mode: ab", "iface: eth0", "debt_bytes: 200", "last_error: below_min_deficit"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status missing %q:\n%s", want, got)
		}
	}
}

func newTestSeed(size int) []byte {
	seed := make([]byte, size)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func writeTestSeedFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "seed.bin")
	if err := os.WriteFile(path, newTestSeed(4096), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return path
}

type hookConfig struct {
	now        func() time.Time
	read       func(string) (ifaceBytes, error)
	detect     func() (string, error)
	pull       func(pullOptions) (uint64, error)
	randomIntn func(int) (int, error)
}

func withMaskHooks(t *testing.T, cfg hookConfig) {
	t.Helper()
	oldNow := nowFunc
	oldRead := readIfaceBytesFunc
	oldDetect := detectDefaultIfaceFunc
	oldPull := pullOnceFunc
	oldRandom := randomIntnFunc
	if cfg.now != nil {
		nowFunc = cfg.now
	}
	if cfg.read != nil {
		readIfaceBytesFunc = cfg.read
	}
	if cfg.detect != nil {
		detectDefaultIfaceFunc = cfg.detect
	}
	if cfg.pull != nil {
		pullOnceFunc = cfg.pull
	}
	if cfg.randomIntn != nil {
		randomIntnFunc = cfg.randomIntn
	}
	t.Cleanup(func() {
		nowFunc = oldNow
		readIfaceBytesFunc = oldRead
		detectDefaultIfaceFunc = oldDetect
		pullOnceFunc = oldPull
		randomIntnFunc = oldRandom
	})
}

func openMaskTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "nwall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustSavePolicy(t *testing.T, db *store.DB, policy store.DownmaskPolicy) {
	t.Helper()
	if policy.MaxRatio == 0 {
		policy.MaxRatio = policy.MinRatio
	}
	if err := db.SaveDownmaskPolicy(policy); err != nil {
		t.Fatalf("SaveDownmaskPolicy: %v", err)
	}
}

func mustSaveABConfig(t *testing.T, db *store.DB, cfg store.DownmaskABPullConfig) {
	t.Helper()
	if cfg.ParallelLimit == 0 {
		cfg.ParallelLimit = 1
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.SpeedLimit == "" {
		cfg.SpeedLimit = "0"
	}
	if err := db.SaveDownmaskABPullConfig(cfg); err != nil {
		t.Fatalf("SaveDownmaskABPullConfig: %v", err)
	}
}

func startPullTestServer(t *testing.T, protocol, serverToken string, seed []byte, status *serveStatus) (int, func()) {
	t.Helper()

	src, err := newSeedReader(seed)
	if err != nil {
		t.Fatalf("newSeedReader: %v", err)
	}

	if protocol == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handleTCPSession(conn, tokenDigest(serverToken), src, 0, status)
		}()
		return ln.Addr().(*net.TCPAddr).Port, func() {
			_ = ln.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("tcp test server did not stop")
			}
		}
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go serveUDPLoop(pc, tokenDigest(serverToken), src, 0, udpDefaultPayload, status)
	return pc.LocalAddr().(*net.UDPAddr).Port, func() {
		_ = pc.Close()
	}
}

type recordingPacketConn struct {
	mu      sync.Mutex
	packets [][]byte
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{}
}

func (r *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (r *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := append([]byte(nil), p...)
	r.packets = append(r.packets, cp)
	return len(p), nil
}

func (r *recordingPacketConn) payloadStats() (totalPayload, maxPacketLen int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pkt := range r.packets {
		if len(pkt) < udpSessionLen {
			continue
		}
		totalPayload += len(pkt) - udpSessionLen
		if len(pkt) > maxPacketLen {
			maxPacketLen = len(pkt)
		}
	}
	return totalPayload, maxPacketLen
}

func (r *recordingPacketConn) Close() error                     { return nil }
func (r *recordingPacketConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (r *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (r *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return string(d) }

func captureStdout(t *testing.T) (func() string, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- string(buf)
	}()
	get := func() string {
		_ = w.Close()
		os.Stdout = orig
		return <-done
	}
	restore := func() {
		os.Stdout = orig
	}
	return get, restore
}
