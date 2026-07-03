// Package conf defines nwall configuration models, defaults, and validation.
package conf

// Config 是 nwall 的完整配置聚合模型。
type Config struct {
	Protect      Protect
	Ingress      Ingress
	Egress       Egress
	Lease        Lease
	LeaseTrigger LeaseTrigger
}

// Protect 控制全机防护的总开关与端口分流。
type Protect struct {
	Enabled            bool
	RollbackTimeoutSec int
	GuardAll           bool
	OpenPortRanges     []PortRange
	OpenPorts          []int
	GuardedPorts       []int
	BlockHTTP          bool
	BlockTLS           bool
	BlockSOCKS         bool
	ProtocolSkipPorts  []int
}

// PortRange preserves a user-visible port item while OpenPorts remains the
// expanded rule input for existing render paths.
type PortRange struct {
	Start int
	End   int
}

// Ingress 是入站白名单配置。
type Ingress struct {
	Enabled      bool
	CNMode       string // off | all | provinces
	CNProvinces  []string
	CNCityCodes  []string
	CustomCIDRs  []string
	PortPolicies []PortPolicy
}

// PortPolicy 是单个监听端口的入站白名单覆盖策略。
type PortPolicy struct {
	ListenPort  int
	CNMode      string // off | all | provinces
	CNProvinces []string
	CNCityCodes []string
}

// Egress 是出站白名单配置。
type Egress struct {
	Enabled     bool
	CNMode      string // off | all | provinces
	CNProvinces []string
	CustomCIDRs []string
}

// Lease 是 TCP 租约 agent 与租约路由配置。
type Lease struct {
	ListenHost        string
	ListenPort        int
	LeaseKey          string
	IdleTTL           string
	TSWindowSec       int
	TrustedRelayCIDRs []string
	Routes            []Route
}

// Route 描述一条租约放行策略。
type Route struct {
	Label         string
	IdleTTL       string
	IPv4PrefixLen int
	IPv6PrefixLen int
	IPAllowCIDRs  []string
}

// LeaseTrigger 是公网 token 触发器配置；触发器只把 HTTP token 请求转成 TCP 租约消息。
type LeaseTrigger struct {
	Enabled           bool
	ListenHost        string
	ListenPort        int
	TrustedProxyCIDRs []string
	Routes            []TriggerRoute
}

// TriggerRoute 描述一个公网 token 到 TCP agent 的转发目标。
type TriggerRoute struct {
	Token         string
	Label         string
	Target        string
	IdleTTL       string
	IPv4PrefixLen int
	IPv6PrefixLen int
}

// Default 返回一份安全的默认配置（防护关闭，SSH 端口默认公开作为破窗保险）。
func Default() Config {
	return Config{
		Protect: Protect{
			Enabled:            false,
			RollbackTimeoutSec: 10,
			GuardAll:           true,
			OpenPortRanges:     []PortRange{{Start: 22, End: 22}},
			OpenPorts:          []int{22},
			GuardedPorts:       []int{},
			ProtocolSkipPorts:  []int{22},
		},
		Ingress: Ingress{Enabled: false, CNMode: "off"},
		Egress:  Egress{Enabled: false, CNMode: "all"},
		Lease: Lease{
			ListenHost:  "127.0.0.1",
			ListenPort:  18080,
			IdleTTL:     "3d",
			TSWindowSec: 60,
		},
		LeaseTrigger: LeaseTrigger{
			Enabled:    true,
			ListenHost: "127.0.0.1",
			ListenPort: 18081,
		},
	}
}
