package cli

import (
	"fmt"
	"strconv"

	"github.com/mora1n/nwall/internal/conf"
)

func runDPI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall dpi http|tls|socks on|off | skip-port add|del|list <port>")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "http", "tls", "socks":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall dpi %s on|off", args[0])
		}
		on, err := parseOnOff(args[1])
		if err != nil {
			return err
		}
		switch args[0] {
		case "http":
			cfg.Protect.BlockHTTP = on
		case "tls":
			cfg.Protect.BlockTLS = on
		case "socks":
			cfg.Protect.BlockSOCKS = on
		}
		return saveConfig(cfg, "已更新 DPI "+args[0])
	case "skip-port":
		return dpiSkipPort(cfg, args[1:])
	default:
		return fmt.Errorf("未知 dpi 子命令: %s", args[0])
	}
}

func dpiSkipPort(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall dpi skip-port add|del|list <port>")
	}
	switch args[0] {
	case "list":
		for _, p := range cfg.Protect.ProtocolSkipPorts {
			fmt.Println(p)
		}
		return nil
	case "add":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall dpi skip-port add <port>")
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("无效端口: %s", args[1])
		}
		cfg.Protect.ProtocolSkipPorts = appendPortUnique(cfg.Protect.ProtocolSkipPorts, port)
		return saveConfig(cfg, "已添加 DPI skip port")
	case "del":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall dpi skip-port del <port>")
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("无效端口: %s", args[1])
		}
		next, err := removePort(cfg.Protect.ProtocolSkipPorts, port)
		if err != nil {
			return err
		}
		cfg.Protect.ProtocolSkipPorts = next
		return saveConfig(cfg, "已删除 DPI skip port")
	default:
		return fmt.Errorf("未知 skip-port 子命令: %s", args[0])
	}
}

func parseOnOff(raw string) (bool, error) {
	switch raw {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, fmt.Errorf("必须是 on|off")
	}
}

func appendPortUnique(ports []int, port int) []int {
	for _, p := range ports {
		if p == port {
			return append([]int(nil), ports...)
		}
	}
	out := append([]int(nil), ports...)
	return append(out, port)
}

func removePort(ports []int, port int) ([]int, error) {
	out := make([]int, 0, len(ports))
	found := false
	for _, p := range ports {
		if p == port {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		return nil, fmt.Errorf("未找到端口: %d", port)
	}
	return out, nil
}
