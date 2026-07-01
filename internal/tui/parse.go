package tui

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/store"
)

func parsePortList(raw string) ([]int, error) {
	ranges, err := parsePortRanges(raw)
	if err != nil {
		return nil, err
	}
	return expandPortRangesForTUI(ranges), nil
}

func parsePortRanges(raw string) ([]conf.PortRange, error) {
	values := splitCSV(raw)
	ranges := make([]conf.PortRange, 0, len(values))
	for _, value := range values {
		start, end, err := parsePortListItem(value)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, conf.PortRange{Start: start, End: end})
	}
	return ranges, nil
}

func expandPortRangesForTUI(ranges []conf.PortRange) []int {
	seen := map[int]struct{}{}
	ports := make([]int, 0, len(ranges))
	for _, r := range ranges {
		for port := r.Start; port <= r.End; port++ {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func parsePortListItem(raw string) (int, int, error) {
	value := strings.TrimSpace(raw)
	if strings.Count(value, "-") == 0 {
		port, err := parsePort(value)
		return port, port, err
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("无效端口范围: %s", raw)
	}
	start, err := parsePort(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("无效端口范围: %s", raw)
	}
	end, err := parsePort(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("无效端口范围: %s", raw)
	}
	if start > end {
		return 0, 0, fmt.Errorf("无效端口范围: %s", raw)
	}
	return start, end, nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("无效端口: %s", raw)
	}
	return port, nil
}

func parseIntRange(raw, name string, min, max int) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s 必须位于 %d-%d", name, min, max)
	}
	return value, nil
}

func parsePositiveInt(raw, name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s 必须是正整数", name)
	}
	return value, nil
}

func parseNonNegativeInt(raw, name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s 必须是非负整数", name)
	}
	return value, nil
}

func parseUint64(raw, name string) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s 必须是非负整数", name)
	}
	return value, nil
}

func parseCIDRList(raw string) ([]string, error) {
	values := splitCSV(raw)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, err := parseCIDRLike(value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return uniqueSorted(out), nil
}

func parsePrefixList(raw string) ([]string, error) {
	values := splitCSV(raw)
	out := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("无效 CIDR: %s", value)
		}
		out = append(out, prefix.Masked().String())
	}
	return uniqueSorted(out), nil
}

func parseCIDRLike(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked().String(), nil
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(addr, bits).String(), nil
	}
	return "", fmt.Errorf("无效 IP/CIDR: %s", raw)
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := strings.TrimSpace(field); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func joinInts(values []int) string {
	if len(values) == 0 {
		return "未设置"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprint(value))
	}
	return strings.Join(parts, ",")
}

func portRangesSummary(ranges []conf.PortRange) string {
	if len(ranges) == 0 {
		return "未设置"
	}
	if len(ranges) <= 3 {
		return joinPortRanges(ranges)
	}
	return fmt.Sprintf("%d 项", len(ranges))
}

func joinPortRanges(ranges []conf.PortRange) string {
	if len(ranges) == 0 {
		return "未设置"
	}
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, formatPortRange(r))
	}
	return strings.Join(parts, ",")
}

func formatPortRange(r conf.PortRange) string {
	if r.Start == r.End {
		return fmt.Sprint(r.Start)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

func validatePortRangesNoOverlap(ranges []conf.PortRange) error {
	used := map[int]struct{}{}
	for _, r := range ranges {
		for port := r.Start; port <= r.End; port++ {
			if _, ok := used[port]; ok {
				return fmt.Errorf("公开端口范围重叠: %d", port)
			}
			used[port] = struct{}{}
		}
	}
	return nil
}

func parseIndexSelection(raw string, total int) (map[int]struct{}, error) {
	values := splitCSV(raw)
	if len(values) == 0 {
		return nil, fmt.Errorf("请输入序号")
	}
	out := map[int]struct{}{}
	for _, value := range values {
		start, end, err := parseIndexSelectionItem(value, total)
		if err != nil {
			return nil, err
		}
		for idx := start; idx <= end; idx++ {
			out[idx-1] = struct{}{}
		}
	}
	return out, nil
}

func parseIndexSelectionItem(raw string, total int) (int, int, error) {
	value := strings.TrimSpace(raw)
	if strings.Count(value, "-") == 0 {
		idx, err := parseIndex(value, total)
		return idx, idx, err
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("无效序号范围: %s", raw)
	}
	start, err := parseIndex(parts[0], total)
	if err != nil {
		return 0, 0, err
	}
	end, err := parseIndex(parts[1], total)
	if err != nil {
		return 0, 0, err
	}
	if start > end {
		return 0, 0, fmt.Errorf("无效序号范围: %s", raw)
	}
	return start, end, nil
}

func parseIndex(raw string, total int) (int, error) {
	idx, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || idx < 1 || idx > total {
		return 0, fmt.Errorf("序号必须位于 1-%d: %s", total, raw)
	}
	return idx, nil
}

func removePortRangesByIndex(ranges []conf.PortRange, indexes map[int]struct{}) []conf.PortRange {
	out := make([]conf.PortRange, 0, len(ranges))
	for i, r := range ranges {
		if _, remove := indexes[i]; remove {
			continue
		}
		out = append(out, r)
	}
	return out
}

func splitHostPort(raw string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, fmt.Errorf("无效 HOST:PORT: %w", err)
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("host 不能为空")
	}
	return host, port, nil
}

func validateOptionalListen(raw, name string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	_, _, err := splitHostPort(raw)
	if err != nil {
		return fmt.Errorf("%s 监听地址无效: %w", name, err)
	}
	return nil
}

func validateOptionalIP(raw, name string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if net.ParseIP(raw) == nil {
		return fmt.Errorf("%s 必须是 IP 地址", name)
	}
	return nil
}

func validateTTL(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fmt.Errorf("租约时长不能为空")
	}
	if _, err := time.ParseDuration(value); err == nil {
		return nil
	}
	if !strings.HasSuffix(value, "d") {
		return fmt.Errorf("租约时长必须是 Go duration 或整数天，例如 10m、1h、3d")
	}
	days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
	if err != nil || days <= 0 {
		return fmt.Errorf("无效天数: %s", value)
	}
	return nil
}

func parsePortPolicy(raw string, gdb *geo.DB) (conf.PortPolicy, error) {
	fields := strings.Fields(raw)
	if len(fields) < 2 {
		return conf.PortPolicy{}, fmt.Errorf("格式: <port> <off|all|provinces> [省份,省份] [城市code,城市code]")
	}
	port, err := parsePort(fields[0])
	if err != nil {
		return conf.PortPolicy{}, err
	}
	mode := fields[1]
	if err := validateCNMode(mode); err != nil {
		return conf.PortPolicy{}, err
	}
	provinces := []string{}
	if len(fields) > 2 && fields[2] != "-" {
		provinces = splitCSV(fields[2])
		for _, province := range provinces {
			if !gdb.ProvinceExists(province) {
				return conf.PortPolicy{}, fmt.Errorf("未知省份: %s", province)
			}
		}
	}
	cityCodes := []string{}
	if len(fields) > 3 {
		cityCodes = splitCSV(strings.Join(fields[3:], ","))
		for _, code := range cityCodes {
			if !gdb.CityExists(code) {
				return conf.PortPolicy{}, fmt.Errorf("未知城市 code: %s", code)
			}
		}
	}
	if mode != "provinces" {
		provinces = nil
	}
	return conf.PortPolicy{ListenPort: port, CNMode: mode, CNProvinces: uniqueSorted(provinces), CNCityCodes: uniqueSorted(cityCodes)}, nil
}

func parseLeaseRoute(raw string) (conf.Route, error) {
	fields := strings.Fields(raw)
	if len(fields) < 4 {
		return conf.Route{}, fmt.Errorf("格式: <label> <ttl> <v4:24-32> <v6:128> [allow,allow]")
	}
	if strings.TrimSpace(fields[0]) == "" {
		return conf.Route{}, fmt.Errorf("label 不能为空")
	}
	if err := validateTTL(fields[1]); err != nil {
		return conf.Route{}, err
	}
	v4, err := parseLeaseV4(fields[2])
	if err != nil {
		return conf.Route{}, err
	}
	v6, err := parseLeaseV6(fields[3])
	if err != nil {
		return conf.Route{}, err
	}
	allows := []string{}
	if len(fields) > 4 {
		allows, err = parsePrefixList(strings.Join(fields[4:], ","))
		if err != nil {
			return conf.Route{}, err
		}
	}
	return conf.Route{
		Label:         fields[0],
		IdleTTL:       fields[1],
		IPv4PrefixLen: v4,
		IPv6PrefixLen: v6,
		IPAllowCIDRs:  allows,
	}, nil
}

func parseTriggerRoute(raw string) (conf.TriggerRoute, error) {
	fields := strings.Fields(raw)
	if len(fields) != 6 {
		return conf.TriggerRoute{}, fmt.Errorf("格式: <token> <label> <target-host:port> <ttl> <v4:24-32> <v6:128>")
	}
	if strings.TrimSpace(fields[0]) == "" || strings.Contains(fields[0], "/") {
		return conf.TriggerRoute{}, fmt.Errorf("token 不能为空且不能包含 /")
	}
	if strings.TrimSpace(fields[1]) == "" {
		return conf.TriggerRoute{}, fmt.Errorf("label 不能为空")
	}
	if _, _, err := splitHostPort(fields[2]); err != nil {
		return conf.TriggerRoute{}, err
	}
	if err := validateTTL(fields[3]); err != nil {
		return conf.TriggerRoute{}, err
	}
	v4, err := parseLeaseV4(fields[4])
	if err != nil {
		return conf.TriggerRoute{}, err
	}
	v6, err := parseLeaseV6(fields[5])
	if err != nil {
		return conf.TriggerRoute{}, err
	}
	return conf.TriggerRoute{
		Token:         fields[0],
		Label:         fields[1],
		Target:        fields[2],
		IdleTTL:       fields[3],
		IPv4PrefixLen: v4,
		IPv6PrefixLen: v6,
	}, nil
}

func parseLeaseV4(raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(raw), "/"))
	if err != nil || value < 24 || value > 32 {
		return 0, fmt.Errorf("IPv4 lease prefix length 必须是 24-32")
	}
	return value, nil
}

func parseLeaseV6(raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(raw), "/"))
	if err != nil || value != 128 {
		return 0, fmt.Errorf("IPv6 lease prefix length 只能是 128")
	}
	return value, nil
}

func validateCNMode(mode string) error {
	switch mode {
	case "off", "all", "provinces":
		return nil
	default:
		return fmt.Errorf("CN 模式必须是 off|all|provinces")
	}
}

func parseRatioRange(raw string) (float64, float64, error) {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("格式: <min> <max>")
	}
	minRatio, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || minRatio <= 0 {
		return 0, 0, fmt.Errorf("min_ratio 必须 > 0")
	}
	maxRatio, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || maxRatio <= 0 {
		return 0, 0, fmt.Errorf("max_ratio 必须 > 0")
	}
	if minRatio > maxRatio {
		return 0, 0, fmt.Errorf("min_ratio 不能大于 max_ratio")
	}
	return minRatio, maxRatio, nil
}

func parseTimeWindow(raw string) (string, string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", "", nil
	}
	if len(fields) != 2 {
		return "", "", fmt.Errorf("格式: HH:MM HH:MM")
	}
	if err := validateClockHHMM(fields[0]); err != nil {
		return "", "", fmt.Errorf("start %w", err)
	}
	if err := validateClockHHMM(fields[1]); err != nil {
		return "", "", fmt.Errorf("end %w", err)
	}
	return fields[0], fields[1], nil
}

func validateClockHHMM(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 2 {
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
	return nil
}

func parseABTunables(raw string) (int, int, int, int, error) {
	fields := strings.Fields(raw)
	if len(fields) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("格式: <timeout> <parallel> <speed-jitter%%> <bytes-jitter%%>")
	}
	timeout, err := parseNonNegativeInt(fields[0], "timeout")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	parallel, err := parseIntRange(fields[1], "parallel_limit", 1, math.MaxInt)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	speedJitter, err := parseIntRange(fields[2], "speed_jitter_percent", 0, 100)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	bytesJitter, err := parseIntRange(fields[3], "bytes_jitter_percent", 0, 100)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return timeout, parallel, speedJitter, bytesJitter, nil
}

func parseDownmaskTarget(raw string) (store.DownmaskABTarget, error) {
	fields := strings.Fields(raw)
	if len(fields) < 5 || len(fields) > 7 {
		return store.DownmaskABTarget{}, fmt.Errorf("格式: <host> <port> <weight> <tcp:true|false> <udp:true|false> [local-ip] [key]")
	}
	if strings.TrimSpace(fields[0]) == "" {
		return store.DownmaskABTarget{}, fmt.Errorf("host 不能为空")
	}
	port, err := parseIntRange(fields[1], "port", 0, 65535)
	if err != nil {
		return store.DownmaskABTarget{}, err
	}
	weight, err := parseIntRange(fields[2], "weight", 1, math.MaxInt)
	if err != nil {
		return store.DownmaskABTarget{}, err
	}
	tcp, err := parseBool(fields[3])
	if err != nil {
		return store.DownmaskABTarget{}, fmt.Errorf("tcp_enabled %w", err)
	}
	udp, err := parseBool(fields[4])
	if err != nil {
		return store.DownmaskABTarget{}, fmt.Errorf("udp_enabled %w", err)
	}
	localIP := ""
	if len(fields) >= 6 {
		localIP = fields[5]
		if err := validateOptionalIP(localIP, "local_ip"); err != nil {
			return store.DownmaskABTarget{}, err
		}
	}
	token := ""
	if len(fields) == 7 {
		token = fields[6]
	}
	return store.DownmaskABTarget{
		Host:       fields[0],
		Port:       port,
		Weight:     weight,
		TCPEnabled: tcp,
		UDPEnabled: udp,
		LocalIP:    localIP,
		Token:      token,
	}, nil
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

func validateDownmaskPolicy(policy store.DownmaskPolicy) error {
	if policy.PullMode != "off" && policy.PullMode != "ab" {
		return fmt.Errorf("pull_mode 必须是 off|ab")
	}
	if policy.MinRatio <= 0 || policy.MaxRatio <= 0 {
		return fmt.Errorf("min_ratio/max_ratio 必须 > 0")
	}
	if policy.MinRatio > policy.MaxRatio {
		return fmt.Errorf("min_ratio 不能大于 max_ratio")
	}
	if err := validateClockHHMM(policy.TimeWindowStart); err != nil {
		return fmt.Errorf("time_window_start %w", err)
	}
	if err := validateClockHHMM(policy.TimeWindowEnd); err != nil {
		return fmt.Errorf("time_window_end %w", err)
	}
	if policy.MaxJitterSeconds < 0 {
		return fmt.Errorf("max_jitter_seconds 必须 >= 0")
	}
	return nil
}

func validateDownmaskAB(cfg store.DownmaskABPullConfig) error {
	if cfg.Protocol != "tcp" && cfg.Protocol != "udp" {
		return fmt.Errorf("protocol 必须是 tcp|udp")
	}
	if cfg.ProtocolMode != "single" && cfg.ProtocolMode != "parallel" {
		return fmt.Errorf("protocol_mode 必须是 single|parallel")
	}
	if cfg.RemotePort < 0 || cfg.RemotePort > 65535 {
		return fmt.Errorf("remote_port 必须位于 0-65535")
	}
	if err := validateOptionalIP(cfg.LocalIP, "local_ip"); err != nil {
		return err
	}
	if cfg.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds 必须 >= 0")
	}
	if cfg.ParallelLimit < 1 {
		return fmt.Errorf("parallel_limit 必须 >= 1")
	}
	if cfg.SpeedJitterPercent < 0 || cfg.SpeedJitterPercent > 100 {
		return fmt.Errorf("speed_jitter_percent 必须位于 0-100")
	}
	if cfg.BytesJitterPercent < 0 || cfg.BytesJitterPercent > 100 {
		return fmt.Errorf("bytes_jitter_percent 必须位于 0-100")
	}
	return validateRate(cfg.SpeedLimit)
}

func validateDownmaskTarget(target store.DownmaskABTarget) error {
	if strings.TrimSpace(target.Host) == "" {
		return fmt.Errorf("host 不能为空")
	}
	if target.Port < 0 || target.Port > 65535 {
		return fmt.Errorf("port 必须位于 0-65535")
	}
	if target.Weight < 1 {
		return fmt.Errorf("weight 必须 >= 1")
	}
	return validateOptionalIP(target.LocalIP, "local_ip")
}

func validateRate(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" || value == "0" {
		return nil
	}
	lower := strings.ToLower(value)
	units := []string{"gbps", "mbps", "kbps", "gib/s", "mib/s", "kib/s", "gb/s", "mb/s", "kb/s", "g", "m", "k", "b/s"}
	for _, suffix := range units {
		if strings.HasSuffix(lower, suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(lower, suffix))
			if number == "" {
				return fmt.Errorf("speed_limit 缺少数值")
			}
			if parsed, err := strconv.ParseFloat(number, 64); err != nil || parsed < 0 {
				return fmt.Errorf("speed_limit 无效: %s", raw)
			}
			return nil
		}
	}
	if _, err := strconv.ParseUint(lower, 10, 64); err != nil {
		return fmt.Errorf("speed_limit 无效: %s", raw)
	}
	return nil
}

func appendUniqueString(values []string, value string) []string {
	if contains(values, value) {
		return append([]string(nil), values...)
	}
	out := append([]string(nil), values...)
	return append(out, value)
}

func removeString(values []string, value string) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func trimLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}
