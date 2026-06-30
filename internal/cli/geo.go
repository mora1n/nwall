package cli

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/mora1n/nwall/internal/geo"
)

func runGeo(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall geo export|refresh ...")
	}
	switch args[0] {
	case "export":
		return geoExport(args[1:])
	case "refresh":
		return geoRefresh(args[1:])
	default:
		return fmt.Errorf("未知 geo 子命令: %s", args[0])
	}
}

func geoExport(args []string) error {
	fs := flag.NewFlagSet("geo export", flag.ContinueOnError)
	mode := fs.String("mode", "all", "off|all|provinces")
	provinces := fs.String("provinces", "", "逗号分隔省份")
	cities := fs.String("cities", "", "逗号分隔城市 code")
	ipVersion := fs.String("ip-version", "46", "4|6|46")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := geo.Default()
	if err != nil {
		return err
	}
	out := []netip.Prefix{}
	prov, err := db.ExportProvinces(*mode, splitCSV(*provinces))
	if err != nil {
		return err
	}
	out = append(out, prov...)
	if strings.TrimSpace(*cities) != "" {
		city, err := db.ExportCities(splitCSV(*cities))
		if err != nil {
			return err
		}
		out = append(out, city...)
	}
	for _, p := range out {
		switch *ipVersion {
		case "4":
			if p.Addr().Is4() {
				fmt.Println(p)
			}
		case "6":
			if p.Addr().Is6() {
				fmt.Println(p)
			}
		case "46":
			fmt.Println(p)
		default:
			return fmt.Errorf("无效 ip-version: %s", *ipVersion)
		}
	}
	return nil
}

func geoRefresh(args []string) error {
	fs := flag.NewFlagSet("geo refresh", flag.ContinueOnError)
	assetDir := fs.String("asset-dir", "internal/geo/assets", "geo asset output dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tool := strings.TrimSpace(os.Getenv("NWALL_GEOBUILD"))
	if tool == "" {
		var err error
		tool, err = exec.LookPath("nwall-geobuild")
		if err != nil {
			return fmt.Errorf("缺少 nwall-geobuild；请先执行 `go build -tags geobuild -o nwall-geobuild ./cmd/geobuild`，或设置 NWALL_GEOBUILD")
		}
	}
	cmd := exec.Command(tool, "--asset-dir", *assetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func splitCSV(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
