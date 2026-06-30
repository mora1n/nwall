package mask

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mora1n/nwall/internal/store"
	appversion "github.com/mora1n/nwall/internal/version"
)

const (
	protoMagic        uint32 = 0x70667764
	protoVersion      uint8  = 1
	headerSize               = 56
	udpSessionLen            = 16
	udpDefaultPayload        = 1200
	udpMinPayload            = udpSessionLen + 1
	udpMaxPayload            = 65507
	udpMaxRetries            = 3
)

var (
	nowFunc            = time.Now
	readIfaceBytesFunc = readIfaceBytes
	pullOnceFunc       = pullOnce
	randomIntnFunc     = cryptoRandIntn
)

func validateUDPPayloadBytes(payload int) error {
	if payload < udpMinPayload || payload > udpMaxPayload {
		return fmt.Errorf("udp payload 必须位于 %d-%d 字节", udpMinPayload, udpMaxPayload)
	}
	return nil
}

type requestHeader struct {
	Magic       uint32
	Version     uint8
	_pad0       uint8
	_pad1       uint16
	TokenSHA256 [32]byte
	WantedBytes uint64
	SpeedLimit  uint64
}

func (h *requestHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, headerSize)
	binary.BigEndian.PutUint32(buf[0:4], h.Magic)
	buf[4] = h.Version
	copy(buf[8:40], h.TokenSHA256[:])
	binary.BigEndian.PutUint64(buf[40:48], h.WantedBytes)
	binary.BigEndian.PutUint64(buf[48:56], h.SpeedLimit)
	return buf, nil
}

func (h *requestHeader) UnmarshalBinary(buf []byte) error {
	if len(buf) < headerSize {
		return fmt.Errorf("请求头长度不足: %d", len(buf))
	}
	h.Magic = binary.BigEndian.Uint32(buf[0:4])
	h.Version = buf[4]
	copy(h.TokenSHA256[:], buf[8:40])
	h.WantedBytes = binary.BigEndian.Uint64(buf[40:48])
	h.SpeedLimit = binary.BigEndian.Uint64(buf[48:56])
	if h.Magic != protoMagic {
		return fmt.Errorf("magic 不匹配: %x", h.Magic)
	}
	if h.Version != protoVersion {
		return fmt.Errorf("不支持的协议版本: %d", h.Version)
	}
	return nil
}

type seedSource interface {
	ReadRandom(buf []byte) error
}

type memorySeedSource struct {
	seed []byte
}

func newSeedReader(seed []byte) (*memorySeedSource, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed 不能为空")
	}
	return &memorySeedSource{seed: seed}, nil
}

func (r *memorySeedSource) ReadRandom(buf []byte) error {
	size := len(buf)
	if size == 0 {
		return nil
	}
	if size < 0 {
		return fmt.Errorf("无效 slice 大小: %d", size)
	}
	if size >= len(r.seed) {
		return r.readWrapped(buf)
	}
	offset, err := cryptoRandIntn(len(r.seed) - size + 1)
	if err != nil {
		return err
	}
	copy(buf, r.seed[offset:offset+size])
	return nil
}

func (r *memorySeedSource) randomSlice(size int) ([]byte, error) {
	buf := make([]byte, size)
	if err := r.ReadRandom(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *memorySeedSource) readWrapped(buf []byte) error {
	pos := 0
	for pos < len(buf) {
		offset, err := cryptoRandIntn(len(r.seed))
		if err != nil {
			return err
		}
		n := copy(buf[pos:], r.seed[offset:])
		pos += n
	}
	return nil
}

type fileSeedSource struct {
	f    *os.File
	size int64
}

func newFileSeedSource(path string) (*fileSeedSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Size() <= 0 {
		_ = f.Close()
		return nil, errors.New("seed 不能为空")
	}
	return &fileSeedSource{f: f, size: info.Size()}, nil
}

func (r *fileSeedSource) Close() error {
	if r == nil || r.f == nil {
		return nil
	}
	return r.f.Close()
}

func (r *fileSeedSource) ReadRandom(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if r.size <= 0 {
		return errors.New("seed 不能为空")
	}
	var offset int64
	var err error
	if int64(len(buf)) < r.size {
		offsetLimit := int(r.size - int64(len(buf)) + 1)
		randomOffset, offsetErr := cryptoRandIntn(offsetLimit)
		if offsetErr != nil {
			return offsetErr
		}
		offset = int64(randomOffset)
	} else {
		randomOffset, offsetErr := cryptoRandIntn(int(r.size))
		if offsetErr != nil {
			return offsetErr
		}
		offset = int64(randomOffset)
	}
	pos := 0
	for pos < len(buf) {
		n, readErr := r.f.ReadAt(buf[pos:], offset)
		pos += n
		if pos >= len(buf) {
			return nil
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		offset = 0
	}
	return err
}

func cryptoRandIntn(limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("无效随机上界: %d", limit)
	}
	if limit == 1 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(limit)), nil
}

func tokenDigest(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// Run 执行 nwall downmask 子命令。
func Run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("缺少子命令")
	}
	switch args[0] {
	case "pull":
		return runPull(args[1:])
	case "serve":
		return runServe(args[1:])
	case "seed":
		return runSeed(args[1:])
	case "config":
		return runConfig(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "ab-pull":
		return runABPullConfig(args[1:])
	case "reconcile":
		return runReconcile(args[1:])
	case "status":
		return runStatus(args[1:])
	case "version", "--version", "-v":
		fmt.Println(appversion.Version)
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("未知子命令: %s", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `nwall downmask - 下行伪装

用法:
  nwall downmask pull   --protocol tcp|udp --remote-host HOST(IP) --remote-port PORT --token <downmask-token> --wanted-bytes N [--speed-limit BPS] [--timeout SEC]
  nwall downmask config set --tcp-addr HOST:PORT --token <downmask-token>
  nwall downmask policy set --pull-mode off|ab --iface IFACE --min-ratio N --max-ratio N
  nwall downmask ab-pull set --protocol tcp|udp --protocol-mode single|parallel --remote-port PORT --token <downmask-token>
  nwall downmask ab-pull targets add <host> [--port PORT] [--token <downmask-token>] [--local-ip IP] [--weight N] [--tcp-enabled true|false] [--udp-enabled true|false]
  nwall downmask reconcile
  nwall downmask status
  nwall downmask serve  [--tcp-addr HOST:PORT] [--udp-addr HOST:PORT] [--token <downmask-token>] [--seed-file PATH] [--max-rate BPS] [--udp-payload-bytes N(17-65507)] [--status-file PATH]
  nwall downmask seed   [--path PATH] [--size BYTES]
  nwall downmask version

说明:
  reconcile 根据网卡 RX/TX 差额自动拉取下行伪装流量，当前支持 AB 模式。
  policy 控制何时拉取；ab-pull 控制从哪些服务端目标拉取；status 查看策略、日状态和服务端状态。
  <downmask-token> 是服务端和客户端一致的下行伪装共享令牌，可用 openssl rand -hex 16 生成；它不是公网触发器 URL 的 <token>。
  serve 不带参数时从 /var/lib/nwall/nwall.db 读取服务端配置和种子。`)
}

func runConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		db, err := store.Open(storePath())
		if err != nil {
			return err
		}
		defer db.Close()
		cfg, err := db.LoadDownmaskConfig()
		if err != nil {
			return err
		}
		fmt.Printf("tcp_addr: %s\n", cfg.TCPAddr)
		fmt.Printf("udp_addr: %s\n", cfg.UDPAddr)
		fmt.Printf("token: %s\n", secretState(cfg.Token))
		fmt.Printf("max_rate: %d\n", cfg.MaxRate)
		fmt.Printf("udp_payload_bytes: %d\n", cfg.UDPPayloadBytes)
		size, err := db.SeedSize()
		if err != nil {
			return err
		}
		fmt.Printf("seed_bytes: %d\n", size)
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("用法: nwall downmask config show|set ...")
	}
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	cfg, err := db.LoadDownmaskConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("downmask config set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var tcpAddr string
	var udpAddr string
	var token string
	var maxRate uint64
	var udpPayload int
	fs.StringVar(&tcpAddr, "tcp-addr", "", "TCP 监听地址，例 0.0.0.0:15301")
	fs.StringVar(&udpAddr, "udp-addr", "", "UDP 监听地址，例 0.0.0.0:15301")
	fs.StringVar(&token, "token", "", "下行伪装共享令牌")
	fs.Uint64Var(&maxRate, "max-rate", 0, "服务端每会话最大发送速率 bytes/s，0 表示不限")
	fs.IntVar(&udpPayload, "udp-payload-bytes", udpDefaultPayload, "UDP 单包 payload 字节")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	seen := visitedFlags(fs)
	if seen["tcp-addr"] {
		if err := validateListenAddr("tcp-addr", tcpAddr); err != nil {
			return err
		}
		cfg.TCPAddr = tcpAddr
	}
	if seen["udp-addr"] {
		if err := validateListenAddr("udp-addr", udpAddr); err != nil {
			return err
		}
		cfg.UDPAddr = udpAddr
	}
	if seen["token"] {
		cfg.Token = token
	}
	if seen["max-rate"] {
		cfg.MaxRate = maxRate
	}
	if seen["udp-payload-bytes"] {
		if err := validateUDPPayloadBytes(udpPayload); err != nil {
			return err
		}
		cfg.UDPPayloadBytes = udpPayload
	}
	if err := db.SaveDownmaskConfig(cfg); err != nil {
		return err
	}
	fmt.Println("已更新下行伪装配置")
	return nil
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})
	return seen
}

func validateListenAddr(name, value string) error {
	if value == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		return fmt.Errorf("--%s 无效: %w", name, err)
	}
	return nil
}

func secretState(value string) string {
	if value == "" {
		return "未设置"
	}
	return "已设置"
}

func runPolicy(args []string) error {
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	if len(args) == 0 || args[0] == "show" {
		policy, err := db.LoadDownmaskPolicy()
		if err != nil {
			return err
		}
		fmt.Printf("pull_mode: %s\n", policy.PullMode)
		fmt.Printf("iface: %s\n", policy.Iface)
		fmt.Printf("min_ratio: %.4f\n", policy.MinRatio)
		fmt.Printf("max_ratio: %.4f\n", policy.MaxRatio)
		fmt.Printf("time_window_start: %s\n", policy.TimeWindowStart)
		fmt.Printf("time_window_end: %s\n", policy.TimeWindowEnd)
		fmt.Printf("max_jitter_seconds: %d\n", policy.MaxJitterSeconds)
		fmt.Printf("min_deficit_bytes: %d\n", policy.MinDeficitBytes)
		fmt.Printf("max_bytes_per_run: %d\n", policy.MaxBytesPerRun)
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("用法: nwall downmask policy show|set ...")
	}
	policy, err := db.LoadDownmaskPolicy()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("downmask policy set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pullMode := fs.String("pull-mode", "", "off|ab")
	iface := fs.String("iface", "", "统计网卡名")
	minRatio := fs.Float64("min-ratio", 0, "每日随机目标比例下限")
	maxRatio := fs.Float64("max-ratio", 0, "每日随机目标比例上限")
	tws := fs.String("time-window-start", "", "HH:MM；留空表示全天")
	twe := fs.String("time-window-end", "", "HH:MM；留空表示全天")
	maxJitter := fs.Int("max-jitter", -1, "每次拉取后的最大随机等待秒数")
	minDeficit := fs.Uint64("min-deficit-bytes", 0, "触发拉取的最小缺口字节")
	maxRun := fs.Uint64("max-bytes-per-run", 0, "单次最大拉取字节")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	seen := visitedFlags(fs)
	if seen["pull-mode"] {
		if err := validatePullMode(*pullMode); err != nil {
			return err
		}
		policy.PullMode = *pullMode
	}
	if seen["iface"] {
		policy.Iface = *iface
	}
	if seen["min-ratio"] {
		if *minRatio <= 0 {
			return errors.New("--min-ratio 必须 > 0")
		}
		policy.MinRatio = *minRatio
	}
	if seen["max-ratio"] {
		if *maxRatio <= 0 {
			return errors.New("--max-ratio 必须 > 0")
		}
		policy.MaxRatio = *maxRatio
	}
	if policy.MinRatio > policy.MaxRatio {
		return errors.New("--min-ratio 不能大于 --max-ratio")
	}
	if seen["time-window-start"] {
		if err := validateClockHHMM(*tws); err != nil {
			return fmt.Errorf("--time-window-start %w", err)
		}
		policy.TimeWindowStart = *tws
	}
	if seen["time-window-end"] {
		if err := validateClockHHMM(*twe); err != nil {
			return fmt.Errorf("--time-window-end %w", err)
		}
		policy.TimeWindowEnd = *twe
	}
	if seen["max-jitter"] {
		if *maxJitter < 0 {
			return errors.New("--max-jitter 必须 >= 0")
		}
		policy.MaxJitterSeconds = *maxJitter
	}
	if seen["min-deficit-bytes"] {
		policy.MinDeficitBytes = *minDeficit
	}
	if seen["max-bytes-per-run"] {
		policy.MaxBytesPerRun = *maxRun
	}
	if err := db.SaveDownmaskPolicy(policy); err != nil {
		return err
	}
	fmt.Println("已更新下行伪装策略")
	return nil
}

func runABPullConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		return printABPullConfig()
	}
	switch args[0] {
	case "set":
		return runABPullSet(args[1:])
	case "targets":
		return runABPullTargets(args[1:])
	default:
		return fmt.Errorf("用法: nwall downmask ab-pull show|set|targets ...")
	}
}

func printABPullConfig() error {
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	cfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		return err
	}
	targets, err := db.LoadDownmaskABTargets()
	if err != nil {
		return err
	}
	fmt.Printf("protocol: %s\n", cfg.Protocol)
	fmt.Printf("protocol_mode: %s\n", cfg.ProtocolMode)
	fmt.Printf("tcp_enabled: %v\n", cfg.TCPEnabled)
	fmt.Printf("udp_enabled: %v\n", cfg.UDPEnabled)
	fmt.Printf("remote_port: %d\n", cfg.RemotePort)
	fmt.Printf("local_ip: %s\n", cfg.LocalIP)
	fmt.Printf("token: %s\n", secretState(cfg.Token))
	fmt.Printf("speed_limit: %s\n", cfg.SpeedLimit)
	fmt.Printf("timeout_seconds: %d\n", cfg.TimeoutSeconds)
	fmt.Printf("parallel_limit: %d\n", cfg.ParallelLimit)
	fmt.Printf("speed_jitter_percent: %d\n", cfg.SpeedJitterPercent)
	fmt.Printf("bytes_jitter_percent: %d\n", cfg.BytesJitterPercent)
	fmt.Printf("targets: %d\n", len(targets))
	return nil
}

func runABPullSet(args []string) error {
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	cfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("downmask ab-pull set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	protocol := fs.String("protocol", "", "tcp|udp")
	mode := fs.String("protocol-mode", "", "single|parallel")
	tcpEnabled := fs.String("tcp-enabled", "", "true|false")
	udpEnabled := fs.String("udp-enabled", "", "true|false")
	remotePort := fs.Int("remote-port", 0, "默认 B 机端口")
	localIP := fs.String("local-ip", "", "本地源 IP，可选")
	token := fs.String("token", "", "默认下行伪装共享令牌")
	speed := fs.String("speed-limit", "", "限速，例如 4194304、4M、32Mbps")
	timeout := fs.Int("timeout", 0, "超时秒数")
	parallelLimit := fs.Int("parallel-limit", 0, "并行协议数量上限")
	speedJitter := fs.Int("speed-jitter-percent", -1, "速度随机浮动百分比")
	bytesJitter := fs.Int("bytes-jitter-percent", -1, "字节数随机浮动百分比")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seen := visitedFlags(fs)
	if seen["protocol"] {
		if err := validateProtocol(*protocol); err != nil {
			return err
		}
		cfg.Protocol = *protocol
	}
	if seen["protocol-mode"] {
		if err := validateProtocolMode(*mode); err != nil {
			return err
		}
		cfg.ProtocolMode = *mode
	}
	if seen["tcp-enabled"] {
		value, err := parseBool(*tcpEnabled)
		if err != nil {
			return fmt.Errorf("--tcp-enabled %w", err)
		}
		cfg.TCPEnabled = value
	}
	if seen["udp-enabled"] {
		value, err := parseBool(*udpEnabled)
		if err != nil {
			return fmt.Errorf("--udp-enabled %w", err)
		}
		cfg.UDPEnabled = value
	}
	if seen["remote-port"] {
		if *remotePort < 0 || *remotePort > 65535 {
			return errors.New("--remote-port 必须位于 0-65535")
		}
		cfg.RemotePort = *remotePort
	}
	if seen["local-ip"] {
		if *localIP != "" && net.ParseIP(*localIP) == nil {
			return fmt.Errorf("无效 --local-ip: %s", *localIP)
		}
		cfg.LocalIP = *localIP
	}
	if seen["token"] {
		cfg.Token = *token
	}
	if seen["speed-limit"] {
		if _, err := parseRateBytesPerSecond(*speed); err != nil {
			return fmt.Errorf("--speed-limit %w", err)
		}
		cfg.SpeedLimit = *speed
	}
	if seen["timeout"] {
		if *timeout < 0 {
			return errors.New("--timeout 必须 >= 0")
		}
		cfg.TimeoutSeconds = *timeout
	}
	if seen["parallel-limit"] {
		if *parallelLimit < 1 {
			return errors.New("--parallel-limit 必须 >= 1")
		}
		cfg.ParallelLimit = *parallelLimit
	}
	if seen["speed-jitter-percent"] {
		if err := validatePercent(*speedJitter); err != nil {
			return fmt.Errorf("--speed-jitter-percent %w", err)
		}
		cfg.SpeedJitterPercent = *speedJitter
	}
	if seen["bytes-jitter-percent"] {
		if err := validatePercent(*bytesJitter); err != nil {
			return fmt.Errorf("--bytes-jitter-percent %w", err)
		}
		cfg.BytesJitterPercent = *bytesJitter
	}
	if err := db.SaveDownmaskABPullConfig(cfg); err != nil {
		return err
	}
	fmt.Println("已更新 AB 拉流配置")
	return nil
}

func runABPullTargets(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "list":
		targets, err := db.LoadDownmaskABTargets()
		if err != nil {
			return err
		}
		for _, t := range targets {
			fmt.Printf("%s\t%d\t%d\t%v\t%v\t%s\t%s\n", t.Host, t.Port, t.Weight, t.TCPEnabled, t.UDPEnabled, valueOrDash(t.LocalIP), secretState(t.Token))
		}
		return nil
	case "clear":
		if err := db.ClearDownmaskABTargets(); err != nil {
			return err
		}
		fmt.Println("已清空 AB 拉流目标")
		return nil
	case "delete", "del":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall downmask ab-pull targets delete <host>")
		}
		ok, err := db.DeleteDownmaskABTarget(args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("未找到 AB 拉流目标: %s", args[1])
		}
		fmt.Println("已删除 AB 拉流目标: " + args[1])
		return nil
	case "add", "update":
		return upsertABPullTarget(db, args[1:])
	default:
		return fmt.Errorf("用法: nwall downmask ab-pull targets list|add|update|delete|clear")
	}
}

func upsertABPullTarget(db *store.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall downmask ab-pull targets add <host> [--port PORT] [--token TOKEN] [--local-ip IP] [--weight N]")
	}
	target := store.DownmaskABTarget{
		Host:       args[0],
		Weight:     1,
		TCPEnabled: true,
		UDPEnabled: true,
	}
	if strings.TrimSpace(target.Host) == "" {
		return errors.New("host 不能为空")
	}
	fs := flag.NewFlagSet("downmask ab-pull targets add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	port := fs.Int("port", 0, "目标端口，0=使用全局 remote_port")
	token := fs.String("token", "", "目标专用下行伪装共享令牌")
	localIP := fs.String("local-ip", "", "目标专用本地源 IP")
	weight := fs.Int("weight", 1, "权重，>=1")
	tcpEnabled := fs.String("tcp-enabled", "true", "true|false")
	udpEnabled := fs.String("udp-enabled", "true", "true|false")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *port < 0 || *port > 65535 {
		return errors.New("--port 必须位于 0-65535")
	}
	target.Port = *port
	target.Token = *token
	if *localIP != "" && net.ParseIP(*localIP) == nil {
		return fmt.Errorf("无效 --local-ip: %s", *localIP)
	}
	target.LocalIP = *localIP
	if *weight < 1 {
		return errors.New("--weight 必须 >= 1")
	}
	target.Weight = *weight
	tcp, err := parseBool(*tcpEnabled)
	if err != nil {
		return fmt.Errorf("--tcp-enabled %w", err)
	}
	udp, err := parseBool(*udpEnabled)
	if err != nil {
		return fmt.Errorf("--udp-enabled %w", err)
	}
	target.TCPEnabled = tcp
	target.UDPEnabled = udp
	if err := db.UpsertDownmaskABTarget(target); err != nil {
		return err
	}
	fmt.Println("已更新 AB 拉流目标: " + target.Host)
	return nil
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// ---- 自动拉取 reconcile/status ----

type ifaceBytes struct {
	RX uint64
	TX uint64
}

type reconcileResult struct {
	Action         string   `json:"action"`
	Reason         string   `json:"reason,omitempty"`
	Iface          string   `json:"iface,omitempty"`
	Date           string   `json:"date,omitempty"`
	TargetRatio    float64  `json:"target_ratio,omitempty"`
	RXAccum        uint64   `json:"rx_accum"`
	TXAccum        uint64   `json:"tx_accum"`
	DebtBytes      uint64   `json:"debt_bytes"`
	PlannedBytes   uint64   `json:"planned_bytes"`
	ActualBytes    uint64   `json:"actual_bytes"`
	NextEligibleAt int64    `json:"next_eligible_at,omitempty"`
	Generation     string   `json:"generation_source,omitempty"`
	PreviousDate   string   `json:"previous_date,omitempty"`
	PreviousRatio  *float64 `json:"previous_target_ratio,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

type pullAttempt struct {
	Protocol string
	Planned  uint64
	Target   store.DownmaskABTarget
	Options  pullOptions
	Actual   uint64
	Err      error
}

type effectiveABTarget struct {
	Host    string
	Port    int
	Token   string
	LocalIP string
}

func runReconcile(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法: nwall downmask reconcile")
	}
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := reconcileDownmask(db)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func runStatus(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法: nwall downmask status")
	}
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	policy, err := db.LoadDownmaskPolicy()
	if err != nil {
		return err
	}
	cfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		return err
	}
	targets, err := db.LoadDownmaskABTargets()
	if err != nil {
		return err
	}
	state, ok, err := db.LoadDownmaskDayState()
	if err != nil {
		return err
	}
	status, statusOK, err := db.LoadDownmaskStatus()
	if err != nil {
		return err
	}
	fmt.Printf("pull_mode: %s\n", policy.PullMode)
	fmt.Printf("iface: %s\n", valueOrDash(policy.Iface))
	fmt.Printf("min_ratio: %.4f\n", policy.MinRatio)
	fmt.Printf("max_ratio: %.4f\n", policy.MaxRatio)
	fmt.Printf("min_deficit_bytes: %d\n", policy.MinDeficitBytes)
	fmt.Printf("max_bytes_per_run: %d\n", policy.MaxBytesPerRun)
	fmt.Printf("ab_protocol_mode: %s\n", cfg.ProtocolMode)
	fmt.Printf("ab_targets: %d\n", len(targets))
	if ok {
		fmt.Printf("date: %s\n", state.Date)
		fmt.Printf("target_ratio: %.4f\n", state.TargetRatio)
		fmt.Printf("rx_accum: %d\n", state.RXAccum)
		fmt.Printf("tx_accum: %d\n", state.TXAccum)
		fmt.Printf("debt_bytes: %d\n", computeDebt(state.TargetRatio, state.RXAccum, state.TXAccum))
		fmt.Printf("last_action: %s\n", state.LastAction)
		fmt.Printf("last_planned_bytes: %d\n", state.LastPlannedBytes)
		fmt.Printf("last_actual_bytes: %d\n", state.LastActualBytes)
		fmt.Printf("last_error: %s\n", valueOrDash(state.LastError))
		fmt.Printf("next_eligible_at: %d\n", state.NextEligibleAt)
		fmt.Printf("generation_source: %s\n", state.GenerationSource)
	}
	if statusOK {
		fmt.Printf("feed_tcp: %v\n", status.TCPListening)
		fmt.Printf("feed_udp: %v\n", status.UDPListening)
		fmt.Printf("feed_bind: %s\n", valueOrDash(status.BindIP))
		fmt.Printf("feed_tcp_port: %d\n", status.TCPPort)
		fmt.Printf("feed_udp_port: %d\n", status.UDPPort)
		fmt.Printf("feed_total_bytes_sent: %d\n", status.TotalBytesSent)
		fmt.Printf("feed_updated_at: %s\n", status.UpdatedAt)
	}
	return nil
}

func reconcileDownmask(db *store.DB) (reconcileResult, error) {
	policy, err := db.LoadDownmaskPolicy()
	if err != nil {
		return reconcileResult{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return reconcileResult{}, err
	}
	if policy.PullMode == "off" {
		return reconcileResult{Action: "off", Reason: "pull_mode_off"}, nil
	}
	if strings.TrimSpace(policy.Iface) == "" {
		return reconcileResult{}, errors.New("downmask policy iface 未设置")
	}

	raw, err := readIfaceBytesFunc(policy.Iface)
	if err != nil {
		return reconcileResult{}, err
	}
	state, err := prepareDayState(db, policy, raw)
	if err != nil {
		return reconcileResult{}, err
	}
	now := nowFunc()
	debt := computeDebt(state.TargetRatio, state.RXAccum, state.TXAccum)
	result := reconcileResult{
		Action:         "skip",
		Iface:          state.Iface,
		Date:           state.Date,
		TargetRatio:    state.TargetRatio,
		RXAccum:        state.RXAccum,
		TXAccum:        state.TXAccum,
		DebtBytes:      debt,
		NextEligibleAt: state.NextEligibleAt,
		Generation:     state.GenerationSource,
		PreviousDate:   state.PreviousDate,
		PreviousRatio:  state.PreviousTargetRatio,
		UpdatedAt:      now.UTC().Format(time.RFC3339),
	}

	action, reason, planned, actual := "skip", "", uint64(0), uint64(0)
	switch {
	case !inTimeWindow(now, policy.TimeWindowStart, policy.TimeWindowEnd):
		reason = "out_of_window"
	case state.NextEligibleAt > 0 && now.Unix() < state.NextEligibleAt:
		reason = "waiting_jitter"
	case debt < policy.MinDeficitBytes:
		reason = "below_min_deficit"
	default:
		planned = debt
		if policy.MaxBytesPerRun > 0 && planned > policy.MaxBytesPerRun {
			planned = policy.MaxBytesPerRun
		}
		actual, err = pullAB(db, planned)
		action = "ab"
		if err != nil {
			reason = err.Error()
		} else if actual == 0 {
			reason = "pull_failed"
		}
		state.NextEligibleAt = nextEligibleUnix(now, policy.MaxJitterSeconds)
		result.NextEligibleAt = state.NextEligibleAt
	}

	state.LastAction = action
	state.LastError = reason
	state.LastPlannedBytes = planned
	state.LastActualBytes = actual
	state.UpdatedAt = result.UpdatedAt
	if err := db.SaveDownmaskDayState(state); err != nil {
		return reconcileResult{}, err
	}
	result.Action = action
	result.Reason = reason
	result.PlannedBytes = planned
	result.ActualBytes = actual
	if err != nil {
		return result, err
	}
	return result, nil
}

func validatePolicy(policy store.DownmaskPolicy) error {
	if err := validatePullMode(policy.PullMode); err != nil {
		return err
	}
	if policy.MinRatio <= 0 || policy.MaxRatio <= 0 {
		return errors.New("min_ratio/max_ratio 必须 > 0")
	}
	if policy.MinRatio > policy.MaxRatio {
		return errors.New("min_ratio 不能大于 max_ratio")
	}
	if policy.MaxJitterSeconds < 0 {
		return errors.New("max_jitter_seconds 必须 >= 0")
	}
	if err := validateClockHHMM(policy.TimeWindowStart); err != nil {
		return fmt.Errorf("time_window_start %w", err)
	}
	if err := validateClockHHMM(policy.TimeWindowEnd); err != nil {
		return fmt.Errorf("time_window_end %w", err)
	}
	return nil
}

func prepareDayState(db *store.DB, policy store.DownmaskPolicy, raw ifaceBytes) (store.DownmaskDayState, error) {
	now := nowFunc()
	today := now.Format("2006-01-02")
	nowISO := now.UTC().Format(time.RFC3339)
	state, ok, err := db.LoadDownmaskDayState()
	if err != nil {
		return store.DownmaskDayState{}, err
	}
	if ok && state.Date == today && state.TargetRatio > 0 && state.Iface == policy.Iface {
		state.RXAccum += counterDelta(raw.RX, state.LastRXRaw)
		state.TXAccum += counterDelta(raw.TX, state.LastTXRaw)
		state.LastRXRaw = raw.RX
		state.LastTXRaw = raw.TX
		state.UpdatedAt = nowISO
		if state.GeneratedAt == "" {
			state.GeneratedAt = nowISO
		}
		if state.GenerationSource == "" {
			state.GenerationSource = "fresh_init"
		}
		if err := db.SaveDownmaskDayState(state); err != nil {
			return store.DownmaskDayState{}, err
		}
		if _, exists, err := db.DownmaskRatioHistoryForDate(today); err != nil {
			return store.DownmaskDayState{}, err
		} else if !exists {
			if err := db.SaveDownmaskRatioHistory(historyFromState(state)); err != nil {
				return store.DownmaskDayState{}, err
			}
		}
		return state, nil
	}
	if history, exists, err := db.DownmaskRatioHistoryForDate(today); err != nil {
		return store.DownmaskDayState{}, err
	} else if exists {
		state = newDayStateFromHistory(policy.Iface, raw, history, nowISO)
		if err := db.SaveDownmaskDayState(state); err != nil {
			return store.DownmaskDayState{}, err
		}
		return state, nil
	}

	previousDate, previousRatio, source, err := previousRatioSource(db, ok, state, today)
	if err != nil {
		return store.DownmaskDayState{}, err
	}
	ratio, err := randomRatio(policy.MinRatio, policy.MaxRatio, previousRatio)
	if err != nil {
		return store.DownmaskDayState{}, err
	}
	state = store.DownmaskDayState{
		Date:                today,
		Iface:               policy.Iface,
		TargetRatio:         ratio,
		LastRXRaw:           raw.RX,
		LastTXRaw:           raw.TX,
		PreviousDate:        previousDate,
		PreviousTargetRatio: previousRatio,
		GenerationSource:    source,
		GeneratedAt:         nowISO,
		LastAction:          "new_day",
		UpdatedAt:           nowISO,
	}
	if err := db.SaveDownmaskDayState(state); err != nil {
		return store.DownmaskDayState{}, err
	}
	if err := db.SaveDownmaskRatioHistory(historyFromState(state)); err != nil {
		return store.DownmaskDayState{}, err
	}
	return state, nil
}

func previousRatioSource(db *store.DB, hasState bool, state store.DownmaskDayState, today string) (string, *float64, string, error) {
	if hasState && state.Date != "" && state.TargetRatio > 0 {
		value := state.TargetRatio
		return state.Date, &value, "rollover_state", nil
	}
	history, ok, err := db.LatestDownmaskRatioHistoryBefore(today)
	if err != nil {
		return "", nil, "", err
	}
	if ok {
		value := history.TargetRatio
		return history.Date, &value, "rollover_history_fallback", nil
	}
	return "", nil, "fresh_init", nil
}

func newDayStateFromHistory(iface string, raw ifaceBytes, history store.DownmaskRatioHistory, nowISO string) store.DownmaskDayState {
	return store.DownmaskDayState{
		Date:                history.Date,
		Iface:               iface,
		TargetRatio:         history.TargetRatio,
		LastRXRaw:           raw.RX,
		LastTXRaw:           raw.TX,
		PreviousDate:        history.PreviousDate,
		PreviousTargetRatio: history.PreviousTargetRatio,
		GenerationSource:    valueDefault(history.GenerationSource, "rollover_history_fallback"),
		GeneratedAt:         valueDefault(history.GeneratedAt, nowISO),
		LastAction:          "state_restore",
		UpdatedAt:           nowISO,
	}
}

func historyFromState(state store.DownmaskDayState) store.DownmaskRatioHistory {
	return store.DownmaskRatioHistory{
		Date:                state.Date,
		TargetRatio:         state.TargetRatio,
		PreviousDate:        state.PreviousDate,
		PreviousTargetRatio: state.PreviousTargetRatio,
		GenerationSource:    state.GenerationSource,
		GeneratedAt:         state.GeneratedAt,
	}
}

func counterDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func computeDebt(ratio float64, rxAccum, txAccum uint64) uint64 {
	debt := ratio*float64(txAccum) - float64(rxAccum)
	if debt <= 0 {
		return 0
	}
	if debt >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Round(debt))
}

func nextEligibleUnix(now time.Time, maxJitterSeconds int) int64 {
	if maxJitterSeconds <= 0 {
		return now.Unix()
	}
	n, err := randomIntnFunc(maxJitterSeconds + 1)
	if err != nil {
		return now.Unix()
	}
	return now.Add(time.Duration(n) * time.Second).Unix()
}

func inTimeWindow(now time.Time, start, end string) bool {
	if start == "" && end == "" {
		return true
	}
	current := now.Hour()*60 + now.Minute()
	startMin := 0
	endMin := 24 * 60
	if start != "" {
		startMin = clockMinutes(start)
	}
	if end != "" {
		endMin = clockMinutes(end)
	}
	if startMin == endMin {
		return true
	}
	if startMin < endMin {
		return current >= startMin && current < endMin
	}
	return current >= startMin || current < endMin
}

func clockMinutes(raw string) int {
	parts := strings.Split(raw, ":")
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	return hour*60 + minute
}

func readIfaceBytes(iface string) (ifaceBytes, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" || strings.Contains(iface, "/") {
		return ifaceBytes{}, fmt.Errorf("无效网卡名: %s", iface)
	}
	base := filepath.Join("/sys/class/net", iface, "statistics")
	rx, err := readUintFile(filepath.Join(base, "rx_bytes"))
	if err != nil {
		return ifaceBytes{}, fmt.Errorf("读取 %s rx_bytes 失败: %w", iface, err)
	}
	tx, err := readUintFile(filepath.Join(base, "tx_bytes"))
	if err != nil {
		return ifaceBytes{}, fmt.Errorf("读取 %s tx_bytes 失败: %w", iface, err)
	}
	return ifaceBytes{RX: rx, TX: tx}, nil
}

func readUintFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效数值 %q: %w", strings.TrimSpace(string(data)), err)
	}
	return value, nil
}

func randomRatio(minRatio, maxRatio float64, previous *float64) (float64, error) {
	if minRatio == maxRatio {
		value := round4(minRatio)
		if previous != nil && value == round4(*previous) {
			return adjustRatio(value, minRatio, maxRatio), nil
		}
		return value, nil
	}
	n, err := randomIntnFunc(1_000_001)
	if err != nil {
		return 0, err
	}
	value := round4(minRatio + (maxRatio-minRatio)*float64(n)/1_000_000)
	if previous != nil && value == round4(*previous) {
		value = adjustRatio(value, minRatio, maxRatio)
	}
	return value, nil
}

func adjustRatio(value, minRatio, maxRatio float64) float64 {
	if minRatio == maxRatio {
		return round4(value)
	}
	adjusted := value + 0.0001
	if adjusted > maxRatio {
		adjusted = value - 0.0001
	}
	if adjusted < minRatio {
		adjusted = minRatio
	}
	return round4(adjusted)
}

func round4(value float64) float64 {
	return math.Round(value*10000) / 10000
}

func pullAB(db *store.DB, planned uint64) (uint64, error) {
	if planned == 0 {
		return 0, nil
	}
	cfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		return 0, err
	}
	if err := validateABConfig(cfg); err != nil {
		return 0, err
	}
	targets, err := db.LoadDownmaskABTargets()
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, errors.New("AB 拉流目标为空")
	}
	if cfg.ProtocolMode == "parallel" {
		return pullABParallel(cfg, targets, planned)
	}
	return pullABProtocol(cfg, targets, cfg.Protocol, planned)
}

func pullABParallel(cfg store.DownmaskABPullConfig, targets []store.DownmaskABTarget, planned uint64) (uint64, error) {
	tcpEnabled := cfg.TCPEnabled
	udpEnabled := cfg.UDPEnabled
	switch {
	case !tcpEnabled && !udpEnabled:
		return 0, errors.New("AB parallel 未启用 tcp/udp")
	case tcpEnabled && udpEnabled:
		tcpPlanned, udpPlanned := splitProtocolBytes(planned)
		if cfg.ParallelLimit >= 2 && udpPlanned > 0 {
			return pullABProtocolsConcurrent(cfg, targets, tcpPlanned, udpPlanned)
		}
		tcpActual, tcpErr := pullABProtocol(cfg, targets, "tcp", tcpPlanned)
		udpActual, udpErr := pullABProtocol(cfg, targets, "udp", udpPlanned)
		return sumABResults(tcpActual, tcpErr, udpActual, udpErr)
	case tcpEnabled:
		return pullABProtocol(cfg, targets, "tcp", planned)
	default:
		return pullABProtocol(cfg, targets, "udp", planned)
	}
}

func pullABProtocolsConcurrent(cfg store.DownmaskABPullConfig, targets []store.DownmaskABTarget, tcpPlanned, udpPlanned uint64) (uint64, error) {
	type result struct {
		actual uint64
		err    error
	}
	tcpCh := make(chan result, 1)
	udpCh := make(chan result, 1)
	go func() {
		actual, err := pullABProtocol(cfg, targets, "tcp", tcpPlanned)
		tcpCh <- result{actual: actual, err: err}
	}()
	go func() {
		actual, err := pullABProtocol(cfg, targets, "udp", udpPlanned)
		udpCh <- result{actual: actual, err: err}
	}()
	tcp := <-tcpCh
	udp := <-udpCh
	return sumABResults(tcp.actual, tcp.err, udp.actual, udp.err)
}

func sumABResults(tcpActual uint64, tcpErr error, udpActual uint64, udpErr error) (uint64, error) {
	total := tcpActual + udpActual
	if total > 0 {
		return total, nil
	}
	if tcpErr != nil && udpErr != nil {
		return 0, fmt.Errorf("tcp: %v; udp: %v", tcpErr, udpErr)
	}
	if tcpErr != nil {
		return 0, tcpErr
	}
	return 0, udpErr
}

func splitProtocolBytes(total uint64) (uint64, uint64) {
	if total <= 1 {
		return total, 0
	}
	n, err := randomIntnFunc(31)
	if err != nil {
		n = 15
	}
	ratio := 35 + n
	tcp := uint64(math.Round(float64(total) * float64(ratio) / 100))
	if tcp < 1 {
		tcp = 1
	}
	if tcp >= total {
		tcp = total - 1
	}
	return tcp, total - tcp
}

func pullABProtocol(cfg store.DownmaskABPullConfig, targets []store.DownmaskABTarget, protocol string, planned uint64) (uint64, error) {
	if planned == 0 {
		return 0, nil
	}
	candidates := protocolTargets(protocol, targets)
	if len(candidates) == 0 {
		return 0, fmt.Errorf("没有可用 %s AB 拉流目标", protocol)
	}
	var lastErr error
	for len(candidates) > 0 {
		idx, err := pickWeightedIndex(candidates)
		if err != nil {
			return 0, err
		}
		target := candidates[idx]
		actual, err := runABPullOnce(cfg, protocol, planned, target)
		if err == nil && actual > 0 {
			return actual, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s 返回 0 字节", target.Host)
		}
		candidates = append(candidates[:idx], candidates[idx+1:]...)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s AB 拉流失败", protocol)
	}
	return 0, lastErr
}

func runABPullOnce(cfg store.DownmaskABPullConfig, protocol string, planned uint64, target store.DownmaskABTarget) (uint64, error) {
	effective, err := resolveABTarget(cfg, target)
	if err != nil {
		return 0, err
	}
	speed, err := parseRateBytesPerSecond(cfg.SpeedLimit)
	if err != nil {
		return 0, err
	}
	wanted := applyPercentJitter(planned, cfg.BytesJitterPercent)
	if wanted < 1 {
		wanted = 1
	}
	if speed > 0 {
		speed = applyPercentJitter(speed, cfg.SpeedJitterPercent)
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 1200 * time.Second
	}
	opts := pullOptions{
		Protocol:    protocol,
		RemoteHost:  effective.Host,
		RemotePort:  effective.Port,
		LocalIP:     effective.LocalIP,
		Token:       effective.Token,
		WantedBytes: wanted,
		SpeedLimit:  speed,
		Timeout:     timeout,
	}
	return pullOnceFunc(opts)
}

func pullOnce(opts pullOptions) (uint64, error) {
	switch opts.Protocol {
	case "tcp":
		return pullTCP(&opts)
	case "udp":
		return pullUDP(&opts)
	default:
		return 0, fmt.Errorf("无效协议: %s", opts.Protocol)
	}
}

func resolveABTarget(cfg store.DownmaskABPullConfig, target store.DownmaskABTarget) (effectiveABTarget, error) {
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return effectiveABTarget{}, errors.New("AB 目标 host 为空")
	}
	port := target.Port
	if port == 0 {
		port = cfg.RemotePort
	}
	if port <= 0 || port > 65535 {
		return effectiveABTarget{}, fmt.Errorf("AB 目标 %s 缺少有效端口", host)
	}
	token := target.Token
	if token == "" {
		token = cfg.Token
	}
	if token == "" {
		return effectiveABTarget{}, fmt.Errorf("AB 目标 %s 缺少 token", host)
	}
	localIP := target.LocalIP
	if localIP == "" {
		localIP = cfg.LocalIP
	}
	return effectiveABTarget{Host: host, Port: port, Token: token, LocalIP: localIP}, nil
}

func protocolTargets(protocol string, targets []store.DownmaskABTarget) []store.DownmaskABTarget {
	out := make([]store.DownmaskABTarget, 0, len(targets))
	for _, target := range targets {
		if target.Weight < 1 || strings.TrimSpace(target.Host) == "" {
			continue
		}
		if protocol == "tcp" && !target.TCPEnabled {
			continue
		}
		if protocol == "udp" && !target.UDPEnabled {
			continue
		}
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Host < out[j].Host
	})
	return out
}

func pickWeightedIndex(targets []store.DownmaskABTarget) (int, error) {
	total := 0
	for _, target := range targets {
		if target.Weight > 0 {
			total += target.Weight
		}
	}
	if total <= 0 {
		return 0, errors.New("AB 目标权重为空")
	}
	pick, err := randomIntnFunc(total)
	if err != nil {
		return 0, err
	}
	accum := 0
	for i, target := range targets {
		accum += target.Weight
		if pick < accum {
			return i, nil
		}
	}
	return len(targets) - 1, nil
}

func applyPercentJitter(value uint64, percent int) uint64 {
	if value == 0 || percent <= 0 {
		return value
	}
	width := percent*2 + 1
	n, err := randomIntnFunc(width)
	if err != nil {
		return value
	}
	delta := n - percent
	factor := 1 + float64(delta)/100
	if factor <= 0 {
		return 1
	}
	out := uint64(math.Round(float64(value) * factor))
	if out == 0 {
		return 1
	}
	return out
}

func validateABConfig(cfg store.DownmaskABPullConfig) error {
	if err := validateProtocol(cfg.Protocol); err != nil {
		return err
	}
	if err := validateProtocolMode(cfg.ProtocolMode); err != nil {
		return err
	}
	if cfg.RemotePort < 0 || cfg.RemotePort > 65535 {
		return errors.New("remote_port 必须位于 0-65535")
	}
	if cfg.LocalIP != "" && net.ParseIP(cfg.LocalIP) == nil {
		return fmt.Errorf("无效 local_ip: %s", cfg.LocalIP)
	}
	if cfg.TimeoutSeconds < 0 {
		return errors.New("timeout_seconds 必须 >= 0")
	}
	if cfg.ParallelLimit < 1 {
		return errors.New("parallel_limit 必须 >= 1")
	}
	if err := validatePercent(cfg.SpeedJitterPercent); err != nil {
		return fmt.Errorf("speed_jitter_percent %w", err)
	}
	if err := validatePercent(cfg.BytesJitterPercent); err != nil {
		return fmt.Errorf("bytes_jitter_percent %w", err)
	}
	_, err := parseRateBytesPerSecond(cfg.SpeedLimit)
	return err
}

func validatePullMode(value string) error {
	if value == "off" || value == "ab" {
		return nil
	}
	return fmt.Errorf("pull_mode 必须是 off|ab")
}

func validateProtocol(value string) error {
	if value == "tcp" || value == "udp" {
		return nil
	}
	return fmt.Errorf("protocol 必须是 tcp|udp")
}

func validateProtocolMode(value string) error {
	if value == "single" || value == "parallel" {
		return nil
	}
	return fmt.Errorf("protocol_mode 必须是 single|parallel")
}

func validateClockHHMM(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("必须是 HH:MM")
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return fmt.Errorf("小时必须是 00-23")
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return fmt.Errorf("分钟必须是 00-59")
	}
	if len(parts[0]) != 2 || len(parts[1]) != 2 {
		return fmt.Errorf("必须是 HH:MM")
	}
	return nil
}

func validatePercent(value int) error {
	if value < 0 || value > 100 {
		return fmt.Errorf("必须位于 0-100")
	}
	return nil
}

func parseBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("必须是 true|false")
	}
}

func parseRateBytesPerSecond(raw string) (uint64, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "0" {
		return 0, nil
	}
	lower := strings.ToLower(value)
	units := []struct {
		suffix string
		mul    float64
	}{
		{suffix: "gbps", mul: 1000 * 1000 * 1000 / 8},
		{suffix: "mbps", mul: 1000 * 1000 / 8},
		{suffix: "kbps", mul: 1000 / 8},
		{suffix: "gib/s", mul: 1024 * 1024 * 1024},
		{suffix: "mib/s", mul: 1024 * 1024},
		{suffix: "kib/s", mul: 1024},
		{suffix: "gb/s", mul: 1000 * 1000 * 1000},
		{suffix: "mb/s", mul: 1000 * 1000},
		{suffix: "kb/s", mul: 1000},
		{suffix: "g", mul: 1024 * 1024 * 1024},
		{suffix: "m", mul: 1024 * 1024},
		{suffix: "k", mul: 1024},
	}
	for _, unit := range units {
		if strings.HasSuffix(lower, unit.suffix) {
			number := strings.TrimSpace(value[:len(value)-len(unit.suffix)])
			return parseRateNumber(number, unit.mul)
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

func parseRateNumber(raw string, mul float64) (uint64, error) {
	if raw == "" {
		return 0, fmt.Errorf("缺少数值")
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("必须 >= 0")
	}
	result := value * mul
	if result > float64(^uint64(0)) {
		return 0, fmt.Errorf("数值过大")
	}
	return uint64(math.Round(result)), nil
}

func valueDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// ---- 限速辅助 ----

type rateLimiter struct {
	bps    uint64
	last   time.Time
	bucket float64
}

func newRateLimiter(bps uint64) *rateLimiter {
	return &rateLimiter{bps: bps, last: time.Now()}
}

func (r *rateLimiter) wait(n int) {
	if r == nil || r.bps == 0 {
		return
	}
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.last = now
	r.bucket += elapsed * float64(r.bps)
	maxBucket := float64(r.bps)
	if r.bucket > maxBucket {
		r.bucket = maxBucket
	}
	r.bucket -= float64(n)
	if r.bucket < 0 {
		sleep := time.Duration(-r.bucket / float64(r.bps) * float64(time.Second))
		time.Sleep(sleep)
		r.last = time.Now()
		r.bucket = 0
	}
}

// ---- pull 子命令 ----

type pullOptions struct {
	Protocol    string
	RemoteHost  string
	RemotePort  int
	LocalIP     string
	Token       string
	WantedBytes uint64
	SpeedLimit  uint64
	Timeout     time.Duration
}

func runPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts pullOptions
	var timeoutSec int
	fs.StringVar(&opts.Protocol, "protocol", "tcp", "tcp|udp")
	fs.StringVar(&opts.RemoteHost, "remote-host", "", "远端主机，建议直填 B 机 IPv4/IPv6")
	fs.IntVar(&opts.RemotePort, "remote-port", 0, "远端端口")
	fs.StringVar(&opts.LocalIP, "local-ip", "", "本地源 IP，可选")
	fs.StringVar(&opts.Token, "token", "", "下行伪装共享令牌，客户端和服务端需一致；可用 openssl rand -hex 16 生成")
	fs.Uint64Var(&opts.WantedBytes, "wanted-bytes", 0, "目标拉流字节")
	fs.Uint64Var(&opts.SpeedLimit, "speed-limit", 0, "限速 bytes/s，0 表示不限")
	fs.IntVar(&timeoutSec, "timeout", 1200, "超时秒数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.Timeout = time.Duration(timeoutSec) * time.Second
	if opts.RemoteHost == "" || opts.RemotePort == 0 {
		return errors.New("--remote-host 和 --remote-port 必填")
	}
	if opts.Token == "" {
		return errors.New("--token 必填")
	}
	if opts.WantedBytes == 0 {
		return errors.New("--wanted-bytes 必须 > 0")
	}

	switch opts.Protocol {
	case "tcp":
		return runPullTCP(&opts)
	case "udp":
		return runPullUDP(&opts)
	default:
		return fmt.Errorf("无效协议: %s", opts.Protocol)
	}
}

type pullResult struct {
	ActualBytes uint64 `json:"actual_bytes"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Protocol    string `json:"protocol"`
}

func emitPullResult(actual uint64, start time.Time, proto string) error {
	result := pullResult{
		ActualBytes: actual,
		ElapsedMs:   time.Since(start).Milliseconds(),
		Protocol:    proto,
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(&result)
}

func runPullTCP(opts *pullOptions) error {
	start := time.Now()
	actual, err := pullTCP(opts)
	if err != nil {
		return err
	}
	return emitPullResult(actual, start, "tcp")
}

func pullTCP(opts *pullOptions) (uint64, error) {
	addr := net.JoinHostPort(opts.RemoteHost, strconv.Itoa(opts.RemotePort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if opts.LocalIP != "" {
		localIP := net.ParseIP(opts.LocalIP)
		if localIP == nil {
			return 0, fmt.Errorf("无效 --local-ip: %s", opts.LocalIP)
		}
		raddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return 0, fmt.Errorf("解析地址失败: %w", err)
		}
		tcpLocal, err := localTCPAddr(localIP, raddr)
		if err != nil {
			return 0, err
		}
		dialer.LocalAddr = tcpLocal
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(opts.Timeout)
	_ = conn.SetDeadline(deadline)

	hdr := requestHeader{
		Magic:       protoMagic,
		Version:     protoVersion,
		TokenSHA256: tokenDigest(opts.Token),
		WantedBytes: opts.WantedBytes,
		SpeedLimit:  opts.SpeedLimit,
	}
	hdrBuf, _ := hdr.MarshalBinary()
	if _, err := conn.Write(hdrBuf); err != nil {
		return 0, fmt.Errorf("写请求头失败: %w", err)
	}

	buf := make([]byte, 32*1024)
	var actual uint64
	for actual < opts.WantedBytes {
		toRead := opts.WantedBytes - actual
		if toRead > uint64(len(buf)) {
			toRead = uint64(len(buf))
		}
		n, err := conn.Read(buf[:toRead])
		if n > 0 {
			actual += uint64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
	}
	return actual, nil
}

func runPullUDP(opts *pullOptions) error {
	start := time.Now()
	actual, err := pullUDP(opts)
	if err != nil {
		return err
	}
	return emitPullResult(actual, start, "udp")
}

func pullUDP(opts *pullOptions) (uint64, error) {
	addr := net.JoinHostPort(opts.RemoteHost, strconv.Itoa(opts.RemotePort))
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, fmt.Errorf("解析地址失败: %w", err)
	}
	var laddr *net.UDPAddr
	if opts.LocalIP != "" {
		localIP := net.ParseIP(opts.LocalIP)
		if localIP == nil {
			return 0, fmt.Errorf("无效 --local-ip: %s", opts.LocalIP)
		}
		laddr, err = localUDPAddr(localIP, raddr)
		if err != nil {
			return 0, err
		}
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return 0, fmt.Errorf("UDP dial 失败: %w", err)
	}
	defer conn.Close()

	var sessionID [udpSessionLen]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return 0, err
	}

	hdr := requestHeader{
		Magic:       protoMagic,
		Version:     protoVersion,
		TokenSHA256: tokenDigest(opts.Token),
		WantedBytes: opts.WantedBytes,
		SpeedLimit:  opts.SpeedLimit,
	}
	hdrBuf, _ := hdr.MarshalBinary()
	requestPkt := append(append([]byte{}, sessionID[:]...), hdrBuf...)

	start := time.Now()
	overallDeadline := start.Add(opts.Timeout)
	var actual uint64
	buf := make([]byte, 65536)

	for attempt := 0; attempt < udpMaxRetries && actual < opts.WantedBytes; attempt++ {
		if _, err := conn.Write(requestPkt); err != nil {
			continue
		}
		idleDeadline := time.Now().Add(5 * time.Second)
		for actual < opts.WantedBytes {
			now := time.Now()
			if now.After(overallDeadline) {
				break
			}
			deadline := overallDeadline
			if idleDeadline.Before(deadline) {
				deadline = idleDeadline
			}
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if n < udpSessionLen {
				continue
			}
			if string(buf[:udpSessionLen]) != string(sessionID[:]) {
				continue
			}
			payload := uint64(n - udpSessionLen)
			actual += payload
			idleDeadline = time.Now().Add(2 * time.Second)
		}
	}
	return actual, nil
}

// ---- serve 子命令 ----

type serveOptions struct {
	TCPAddr    string
	UDPAddr    string
	Token      string
	SeedFile   string
	MaxRate    uint64
	UDPPayload int
	StatusFile string
}

type udpSessionKey struct {
	Addr      string
	SessionID [udpSessionLen]byte
}

type serveStatus struct {
	mu             sync.Mutex
	tcpListening   bool
	udpListening   bool
	bindIP         string
	tcpPort        int
	udpPort        int
	totalBytesSent uint64
	activeSessions int
	udpSessions    map[udpSessionKey]struct{}
}

type serveStatusJSON struct {
	TCPListening   bool   `json:"tcp_listening"`
	UDPListening   bool   `json:"udp_listening"`
	BindIP         string `json:"bind_ip"`
	TCPPort        int    `json:"tcp_port"`
	UDPPort        int    `json:"udp_port"`
	TotalBytesSent uint64 `json:"total_bytes_sent"`
	ActiveSessions int    `json:"active_sessions"`
	UpdatedAt      string `json:"updated_at"`
}

func (s *serveStatus) snapshot() serveStatusJSON {
	s.mu.Lock()
	defer s.mu.Unlock()
	return serveStatusJSON{
		TCPListening:   s.tcpListening,
		UDPListening:   s.udpListening,
		BindIP:         s.bindIP,
		TCPPort:        s.tcpPort,
		UDPPort:        s.udpPort,
		TotalBytesSent: s.totalBytesSent,
		ActiveSessions: s.activeSessions,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts serveOptions
	fs.StringVar(&opts.TCPAddr, "tcp-addr", "", "TCP 监听地址，例 0.0.0.0:15301，空表示不启用")
	fs.StringVar(&opts.UDPAddr, "udp-addr", "", "UDP 监听地址，空表示不启用")
	fs.StringVar(&opts.Token, "token", "", "下行伪装共享令牌，客户端和服务端需一致；可用 openssl rand -hex 16 生成")
	fs.StringVar(&opts.SeedFile, "seed-file", "", "高熵种子文件路径；默认生成路径通常为 /var/lib/nwall/downmask/seed.bin")
	fs.Uint64Var(&opts.MaxRate, "max-rate", 0, "服务端每会话最大发送速率 bytes/s，0 表示不限")
	fs.IntVar(&opts.UDPPayload, "udp-payload-bytes", udpDefaultPayload, "UDP 单包 payload 字节；必须位于 17-65507")
	fs.StringVar(&opts.StatusFile, "status-file", "", "状态 JSON 文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, dbSeed, err := applyDBServeDefaults(&opts)
	if err != nil {
		return err
	}
	if db != nil {
		defer db.Close()
	}
	if opts.Token == "" {
		return errors.New("--token 必填")
	}
	if opts.TCPAddr == "" && opts.UDPAddr == "" {
		return errors.New("必须至少启用 --tcp-addr 或 --udp-addr")
	}
	if err := validateUDPPayloadBytes(opts.UDPPayload); err != nil {
		return fmt.Errorf("--udp-payload-bytes %w", err)
	}

	var seed seedSource
	var closeSeed func() error
	if dbSeed != nil {
		seed = dbSeed
	} else {
		var err error
		seed, closeSeed, err = loadOrGenSeed(opts.SeedFile)
		if err != nil {
			return err
		}
		if closeSeed != nil {
			defer closeSeed()
		}
	}

	expected := tokenDigest(opts.Token)
	status := &serveStatus{
		udpSessions: make(map[udpSessionKey]struct{}),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	stop := make(chan struct{})
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				continue
			}
			close(stop)
			return
		}
	}()

	var wg sync.WaitGroup
	if opts.TCPAddr != "" {
		host, portStr, err := net.SplitHostPort(opts.TCPAddr)
		if err != nil {
			return fmt.Errorf("无效 --tcp-addr: %w", err)
		}
		port, _ := strconv.Atoi(portStr)
		ln, err := net.Listen("tcp", opts.TCPAddr)
		if err != nil {
			return fmt.Errorf("TCP 监听失败 %s: %w", opts.TCPAddr, err)
		}
		status.mu.Lock()
		status.tcpListening = true
		status.bindIP = host
		status.tcpPort = port
		status.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ln.Close()
			go func() { <-stop; ln.Close() }()
			serveTCPLoop(ln, expected, seed, opts.MaxRate, status)
		}()
	}
	if opts.UDPAddr != "" {
		host, portStr, err := net.SplitHostPort(opts.UDPAddr)
		if err != nil {
			return fmt.Errorf("无效 --udp-addr: %w", err)
		}
		port, _ := strconv.Atoi(portStr)
		pc, err := net.ListenPacket("udp", opts.UDPAddr)
		if err != nil {
			return fmt.Errorf("UDP 监听失败 %s: %w", opts.UDPAddr, err)
		}
		status.mu.Lock()
		status.udpListening = true
		if status.bindIP == "" {
			status.bindIP = host
		}
		status.udpPort = port
		status.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer pc.Close()
			go func() { <-stop; pc.Close() }()
			serveUDPLoop(pc, expected, seed, opts.MaxRate, opts.UDPPayload, status)
		}()
	}

	if opts.StatusFile != "" || db != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			writeStatus(opts.StatusFile, db, status)
			for {
				select {
				case <-stop:
					writeStatus(opts.StatusFile, db, status)
					return
				case <-ticker.C:
					writeStatus(opts.StatusFile, db, status)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func applyDBServeDefaults(opts *serveOptions) (*store.DB, seedSource, error) {
	if opts.Token != "" || opts.TCPAddr != "" || opts.UDPAddr != "" || opts.SeedFile != "" || opts.StatusFile != "" {
		return nil, nil, nil
	}
	db, err := store.Open(storePath())
	if err != nil {
		return nil, nil, err
	}
	cfg, err := db.LoadDownmaskConfig()
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	opts.TCPAddr = cfg.TCPAddr
	opts.UDPAddr = cfg.UDPAddr
	opts.Token = cfg.Token
	opts.MaxRate = cfg.MaxRate
	if cfg.UDPPayloadBytes != 0 {
		opts.UDPPayload = cfg.UDPPayloadBytes
	}
	if err := db.EnsureBootstrapSeed(); err != nil {
		db.Close()
		return nil, nil, err
	}
	seed, err := db.NewSeedReader()
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return db, seed, nil
}

func storePath() string {
	if p := os.Getenv("NWALL_DB"); p != "" {
		return p
	}
	return store.DefaultPath
}

func writeStatus(path string, db *store.DB, s *serveStatus) {
	if path != "" {
		writeStatusFile(path, s)
	}
	if db != nil {
		snap := s.snapshot()
		_ = db.SaveDownmaskStatus(store.DownmaskStatus{
			StartedAt:      snap.UpdatedAt,
			TCPListening:   snap.TCPListening,
			UDPListening:   snap.UDPListening,
			BindIP:         snap.BindIP,
			TCPPort:        snap.TCPPort,
			UDPPort:        snap.UDPPort,
			ActiveSessions: snap.ActiveSessions,
			TotalBytesSent: snap.TotalBytesSent,
			UpdatedAt:      snap.UpdatedAt,
		})
	}
}

func writeStatusFile(path string, s *serveStatus) {
	if path == "" {
		return
	}
	snap := s.snapshot()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&snap); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	f.Close()
	_ = os.Rename(tmp, path)
}

func (s *serveStatus) sessionStart() {
	s.mu.Lock()
	s.activeSessions++
	s.mu.Unlock()
}

func (s *serveStatus) sessionDone() {
	s.mu.Lock()
	s.activeSessions--
	s.mu.Unlock()
}

func (s *serveStatus) addSent(n uint64) {
	atomic.AddUint64(&s.totalBytesSent, n)
}

func (s *serveStatus) tryStartUDPSession(key udpSessionKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.udpSessions[key]; exists {
		return false
	}
	s.udpSessions[key] = struct{}{}
	return true
}

func (s *serveStatus) finishUDPSession(key udpSessionKey) {
	s.mu.Lock()
	delete(s.udpSessions, key)
	s.mu.Unlock()
}

func serveTCPLoop(ln net.Listener, expected [32]byte, seed seedSource, maxRate uint64, status *serveStatus) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTCPSession(conn, expected, seed, maxRate, status)
	}
}

func handleTCPSession(conn net.Conn, expected [32]byte, seed seedSource, maxRate uint64, status *serveStatus) {
	defer conn.Close()
	status.sessionStart()
	defer status.sessionDone()

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	hdrBuf := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, hdrBuf); err != nil {
		return
	}
	var hdr requestHeader
	if err := hdr.UnmarshalBinary(hdrBuf); err != nil {
		return
	}
	if hdr.TokenSHA256 != expected {
		return
	}
	rate := hdr.SpeedLimit
	if maxRate > 0 && (rate == 0 || rate > maxRate) {
		rate = maxRate
	}
	limiter := newRateLimiter(rate)

	wanted := hdr.WantedBytes
	if wanted == 0 {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	chunk := 32 * 1024
	if uint64(chunk) > wanted {
		chunk = int(wanted)
	}
	buf := make([]byte, chunk)
	var sent uint64
	for sent < wanted {
		toSend := wanted - sent
		if toSend > uint64(chunk) {
			toSend = uint64(chunk)
		}
		slice := buf[:int(toSend)]
		if err := seed.ReadRandom(slice); err != nil {
			return
		}
		limiter.wait(int(toSend))
		_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := conn.Write(slice); err != nil {
			return
		}
		sent += toSend
		status.addSent(toSend)
	}
}

func serveUDPLoop(pc net.PacketConn, expected [32]byte, seed seedSource, maxRate uint64, payload int, status *serveStatus) {
	buf := make([]byte, 1<<16)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < udpSessionLen+headerSize {
			continue
		}
		var sessionID [udpSessionLen]byte
		copy(sessionID[:], buf[:udpSessionLen])
		var hdr requestHeader
		if err := hdr.UnmarshalBinary(buf[udpSessionLen : udpSessionLen+headerSize]); err != nil {
			continue
		}
		if hdr.TokenSHA256 != expected {
			continue
		}
		rate := hdr.SpeedLimit
		if maxRate > 0 && (rate == 0 || rate > maxRate) {
			rate = maxRate
		}
		key := udpSessionKey{
			Addr:      addr.String(),
			SessionID: sessionID,
		}
		if !status.tryStartUDPSession(key) {
			continue
		}
		go handleUDPSession(pc, addr, sessionID, hdr.WantedBytes, rate, seed, payload, key, status)
	}
}

func handleUDPSession(pc net.PacketConn, addr net.Addr, sessionID [udpSessionLen]byte, wanted uint64, rate uint64, seed seedSource, payload int, key udpSessionKey, status *serveStatus) {
	defer status.finishUDPSession(key)
	if wanted == 0 {
		return
	}
	status.sessionStart()
	defer status.sessionDone()

	limiter := newRateLimiter(rate)
	if err := validateUDPPayloadBytes(payload); err != nil {
		return
	}
	var sent uint64
	deadline := time.Now().Add(10 * time.Minute)
	packet := make([]byte, payload)
	copy(packet[:udpSessionLen], sessionID[:])
	for sent < wanted {
		if time.Now().After(deadline) {
			return
		}
		remaining := wanted - sent
		bodySize := payload - udpSessionLen
		if uint64(bodySize) > remaining {
			bodySize = int(remaining)
		}
		packetLen := udpSessionLen + bodySize
		copy(packet[:udpSessionLen], sessionID[:])
		if err := seed.ReadRandom(packet[udpSessionLen:packetLen]); err != nil {
			return
		}
		limiter.wait(packetLen)
		if _, err := pc.WriteTo(packet[:packetLen], addr); err != nil {
			return
		}
		sent += uint64(bodySize)
		status.addSent(uint64(bodySize))
	}
}

func localTCPAddr(localIP net.IP, remote *net.TCPAddr) (*net.TCPAddr, error) {
	if remote == nil {
		return nil, errors.New("缺少远端地址")
	}
	ip, err := ipForFamily(localIP, remote.IP)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip}, nil
}

func localUDPAddr(localIP net.IP, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if remote == nil {
		return nil, errors.New("缺少远端地址")
	}
	ip, err := ipForFamily(localIP, remote.IP)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip}, nil
}

func ipForFamily(localIP, remoteIP net.IP) (net.IP, error) {
	if localIP == nil {
		return nil, errors.New("本地 IP 解析失败")
	}
	if remoteIP == nil {
		return nil, errors.New("远端 IP 解析失败")
	}
	if remoteIP.To4() != nil {
		if localIP.To4() == nil {
			return nil, fmt.Errorf("本地 IP %s 与远端地址族不匹配", localIP.String())
		}
		return localIP.To4(), nil
	}
	if localIP.To4() != nil {
		return nil, fmt.Errorf("本地 IP %s 与远端地址族不匹配", localIP.String())
	}
	ip := localIP.To16()
	if ip == nil {
		return nil, fmt.Errorf("本地 IP %s 无法用于 IPv6", localIP.String())
	}
	return ip, nil
}

func loadOrGenSeed(path string) (seedSource, func() error, error) {
	if path != "" {
		if reader, err := newFileSeedSource(path); err == nil {
			return reader, reader.Close, nil
		}
	}
	buf := make([]byte, 8*1024*1024)
	if _, err := rand.Read(buf); err != nil {
		return nil, nil, err
	}
	reader, err := newSeedReader(buf)
	if err != nil {
		return nil, nil, err
	}
	return reader, nil, nil
}

// ---- seed 子命令 ----

func runSeed(args []string) error {
	if len(args) > 0 && args[0] == "generate" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var path string
	var size int64
	fs.StringVar(&path, "path", "", "兼容旧用法：写入文件路径；默认写入 nwall.db")
	fs.Int64Var(&size, "size", 1024*1024*1024, "种子文件字节大小；默认 1GB，推荐 256MB-4GB")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if size <= 0 {
		return errors.New("--size 必须 > 0")
	}
	if path == "" {
		db, err := store.Open(storePath())
		if err != nil {
			return err
		}
		defer db.Close()
		if err := db.GenerateDownmaskSeed(size); err != nil {
			return err
		}
		fmt.Printf("seed 已生成到 DB: path=%s size=%d\n", storePath(), size)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()
	buf := make([]byte, 1024*1024)
	var written int64
	for written < size {
		toWrite := size - written
		if toWrite > int64(len(buf)) {
			toWrite = int64(len(buf))
		}
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return err
		}
		written += toWrite
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	hash := sha256.New()
	if data, err := os.ReadFile(path); err == nil {
		hash.Write(data)
	}
	fmt.Printf("seed 已生成: path=%s size=%d sha256=%s\n", path, size, hex.EncodeToString(hash.Sum(nil)))
	return nil
}
