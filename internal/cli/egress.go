package cli

import (
	"fmt"
	"strings"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

func runEgress(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall egress enable|disable|status|cn|custom ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "enable":
		cfg.Egress.Enabled = true
		return saveConfig(cfg, "出站白名单已启用（执行 nwall protect apply 生效）")
	case "disable":
		cfg.Egress.Enabled = false
		return saveConfig(cfg, "出站白名单已停用（执行 nwall protect apply 生效）")
	case "status":
		fmt.Printf("enabled: %v\ncn_mode: %s\ncn_provinces: %v\ncustom_cidrs: %v\n", cfg.Egress.Enabled, cfg.Egress.CNMode, cfg.Egress.CNProvinces, cfg.Egress.CustomCIDRs)
		return nil
	case "cn":
		return egressCN(cfg, args[1:])
	case "custom":
		return egressCustom(cfg, args[1:])
	default:
		return fmt.Errorf("未知 egress 子命令: %s", args[0])
	}
}

func egressCN(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall egress cn off|all|list|select <省份...>")
	}
	switch args[0] {
	case "off":
		cfg.Egress.CNMode = "off"
		cfg.Egress.CNProvinces = nil
		return saveConfig(cfg, "已关闭 egress CN 策略")
	case "all":
		cfg.Egress.CNMode = "all"
		cfg.Egress.CNProvinces = nil
		return saveConfig(cfg, "已设为允许全部 CN 出站")
	case "list":
		db, err := geo.Default()
		if err != nil {
			return err
		}
		for _, p := range db.Provinces() {
			fmt.Println(p)
		}
		return nil
	case "select":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall egress cn select <省份...>")
		}
		db, err := geo.Default()
		if err != nil {
			return err
		}
		for _, name := range args[1:] {
			if !db.ProvinceExists(name) {
				return fmt.Errorf("未知省份: %s", name)
			}
		}
		cfg.Egress.CNMode = "provinces"
		cfg.Egress.CNProvinces = append([]string(nil), args[1:]...)
		return saveConfig(cfg, "已设为按省份允许出站: "+strings.Join(args[1:], ", "))
	default:
		return fmt.Errorf("未知 egress cn 子命令: %s", args[0])
	}
}

func egressCustom(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall egress custom add|del|list <CIDR>")
	}
	switch args[0] {
	case "list":
		for _, c := range cfg.Egress.CustomCIDRs {
			fmt.Println(c)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall egress custom add <CIDR>")
		}
		cfg.Egress.CustomCIDRs = appendUnique(cfg.Egress.CustomCIDRs, args[1:]...)
		return saveConfig(cfg, "已添加 egress CIDR: "+strings.Join(args[1:], ", "))
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall egress custom del <CIDR>")
		}
		next, err := removeValues(cfg.Egress.CustomCIDRs, args[1:]...)
		if err != nil {
			return err
		}
		cfg.Egress.CustomCIDRs = next
		return saveConfig(cfg, "已删除 egress CIDR: "+strings.Join(args[1:], ", "))
	default:
		return fmt.Errorf("未知 egress custom 子命令: %s", args[0])
	}
}
