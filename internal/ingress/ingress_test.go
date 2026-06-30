package ingress

import (
	"testing"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

func TestBuildCustomOnly(t *testing.T) {
	cfg := conf.Ingress{
		Enabled:     true,
		CNMode:      "off",
		CustomCIDRs: []string{"203.0.113.5", "198.51.100.0/24", "2001:db8::/32"},
	}
	s, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(s.V4) != 2 {
		t.Errorf("应有 2 个 v4 前缀，得 %d: %v", len(s.V4), s.V4)
	}
	if len(s.V6) != 1 {
		t.Errorf("应有 1 个 v6 前缀，得 %d: %v", len(s.V6), s.V6)
	}
	// 单 IP 应补全为 /32。
	if s.V4[0].String() != "203.0.113.5/32" {
		t.Errorf("单 IP 应补全 /32，得 %s", s.V4[0].String())
	}
}

func TestBuildRejectsBadCIDR(t *testing.T) {
	cfg := conf.Ingress{Enabled: true, CNMode: "off", CustomCIDRs: []string{"not-an-ip"}}
	if _, err := Build(cfg, nil); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}

func TestBuildWithGeoProvinces(t *testing.T) {
	db, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	provs := db.Provinces()
	cfg := conf.Ingress{
		Enabled:     true,
		CNMode:      "provinces",
		CNProvinces: provs[:1],
		CustomCIDRs: []string{"203.0.113.5"},
	}
	s, err := Build(cfg, db)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// 自定义 1 个 + 省份若干。
	if len(s.V4) < 2 {
		t.Errorf("省份模式应展开出多个 v4 前缀，得 %d", len(s.V4))
	}
}

func TestBuildCitiesWhenCNOff(t *testing.T) {
	db, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	code := firstCityWithCIDR(t, db)
	cfg := conf.Ingress{Enabled: true, CNMode: "off", CNCityCodes: []string{code}}
	s, err := Build(cfg, db)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(s.V4) == 0 {
		t.Fatalf("城市 code 应在 cn_mode=off 时仍展开 v4 前缀")
	}
}

func TestBuildPortPolicySources(t *testing.T) {
	db, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	code := firstCityWithCIDR(t, db)
	cfg := conf.Ingress{
		Enabled: true,
		CNMode:  "off",
		PortPolicies: []conf.PortPolicy{{
			ListenPort:  8443,
			CNMode:      "off",
			CNCityCodes: []string{code},
		}},
	}
	s, err := Build(cfg, db)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(s.Ports) != 1 || s.Ports[0].ListenPort != 8443 || len(s.Ports[0].V4) == 0 {
		t.Fatalf("端口策略展开不符: %+v", s.Ports)
	}
}

func TestBuildRejectsUnknownCity(t *testing.T) {
	db, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg := conf.Ingress{Enabled: true, CNMode: "off", CNCityCodes: []string{"000000"}}
	if _, err := Build(cfg, db); err == nil {
		t.Error("未知城市 code 应报错")
	}
}

func firstCityWithCIDR(t *testing.T, db *geo.DB) string {
	t.Helper()
	for _, city := range db.Cities() {
		prefixes, err := db.ExportCities([]string{city.Code})
		if err == nil && len(prefixes) > 0 {
			return city.Code
		}
	}
	t.Fatal("测试 geo 数据中没有可用城市 CIDR")
	return ""
}
