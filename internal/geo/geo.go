package geo

import (
	_ "embed"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed assets/pfwd-geo-cn-v4.bin
var geoV4Raw []byte

//go:embed assets/pfwd-geo-cn-v6.bin
var geoV6Raw []byte

//go:embed assets/pfwd-geo-meta.json
var geoMetaRaw []byte

//go:embed assets/pfwd-city-cn-v4.bin
var cityV4Raw []byte

//go:embed assets/pfwd-city-cn-meta.json
var cityMetaRaw []byte

// DB 是解析后的内嵌地理库，懒加载且并发安全。
type DB struct {
	v4 []prefixV4
	v6 []prefixV6

	cityIdx []cityIndexRecord
	cityPfx []cityPrefixV4

	provinceID   map[string]uint16 // 省名 -> ID
	cityCodeByID map[string]uint32 // 城市 code 文本 -> 数值 code
	cityByCode   map[string]City   // 城市 code 文本 -> 城市信息
}

// City 是可选择的城市 code 与显示名。
type City struct {
	Code     string
	Name     string
	Province string
}

var (
	defaultDB   *DB
	defaultOnce sync.Once
	defaultErr  error
)

// Default 返回内嵌地理库（首次调用解析，后续复用）。
func Default() (*DB, error) {
	defaultOnce.Do(func() {
		defaultDB, defaultErr = load()
	})
	return defaultDB, defaultErr
}

func load() (*DB, error) {
	v4, err := parseGeoV4(geoV4Raw)
	if err != nil {
		return nil, err
	}
	v6, err := parseGeoV6(geoV6Raw)
	if err != nil {
		return nil, err
	}
	gm, err := parseGeoMeta(geoMetaRaw)
	if err != nil {
		return nil, err
	}
	cIdx, cPfx, err := parseCityV4(cityV4Raw)
	if err != nil {
		return nil, err
	}
	cm, err := parseCityMeta(cityMetaRaw)
	if err != nil {
		return nil, err
	}

	db := &DB{
		v4:           v4,
		v6:           v6,
		cityIdx:      cIdx,
		cityPfx:      cPfx,
		provinceID:   make(map[string]uint16, len(gm.Provinces)),
		cityCodeByID: make(map[string]uint32),
		cityByCode:   make(map[string]City),
	}
	for _, p := range gm.Provinces {
		if p.Hidden {
			continue
		}
		db.provinceID[p.Name] = p.ID
	}
	for _, prov := range cm.Provinces {
		for _, c := range prov.Cities {
			code, err := strconv.ParseUint(strings.TrimSpace(c.Code), 10, 32)
			if err != nil {
				continue
			}
			db.cityCodeByID[c.Code] = uint32(code)
			db.cityByCode[c.Code] = City{Code: c.Code, Name: c.Name, Province: prov.Name}
		}
	}
	return db, nil
}

// Provinces 返回所有可选省份名（用于 CLI 列表）。
func (db *DB) Provinces() []string {
	out := make([]string, 0, len(db.provinceID))
	for name := range db.provinceID {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ProvinceExists 报告省份名是否有效。
func (db *DB) ProvinceExists(name string) bool {
	_, ok := db.provinceID[name]
	return ok
}

// Cities 返回所有可选城市 code，按 code 稳定排序。
func (db *DB) Cities() []City {
	out := make([]City, 0, len(db.cityCodeByID))
	for code := range db.cityCodeByID {
		out = append(out, db.cityByCode[code])
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Code < out[j].Code
	})
	return out
}

// CitiesByProvince 返回指定省份下的城市，按 code 稳定排序。
func (db *DB) CitiesByProvince(province string) []City {
	out := []City{}
	for _, city := range db.cityByCode {
		if city.Province == province {
			out = append(out, city)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Code < out[j].Code
	})
	return out
}

// CityProvince 返回城市 code 对应省份。
func (db *DB) CityProvince(code string) (string, bool) {
	city, ok := db.cityByCode[strings.TrimSpace(code)]
	return city.Province, ok
}

// CityExists 报告城市 code 是否有效。
func (db *DB) CityExists(code string) bool {
	_, ok := db.cityCodeByID[strings.TrimSpace(code)]
	return ok
}

// ExportProvinces 返回指定 mode 下的省份 CIDR 列表。
// mode="all" 返回全部 CN CIDR；mode="provinces" 仅返回 provinces 内省份。
func (db *DB) ExportProvinces(mode string, provinces []string) ([]netip.Prefix, error) {
	var allowed map[uint16]struct{}
	switch mode {
	case "all":
		// allowed=nil 表示全部
	case "provinces":
		allowed = make(map[uint16]struct{}, len(provinces))
		for _, name := range provinces {
			id, ok := db.provinceID[strings.TrimSpace(name)]
			if !ok {
				return nil, fmt.Errorf("未知省份：%s", name)
			}
			allowed[id] = struct{}{}
		}
	case "off", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("无效 cn_mode：%s", mode)
	}
	include := func(id uint16) bool {
		if allowed == nil {
			return true
		}
		_, ok := allowed[id]
		return ok
	}
	out := make([]netip.Prefix, 0, len(db.v4)+len(db.v6))
	for _, p := range db.v4 {
		if !include(p.ProvinceID) {
			continue
		}
		c, err := v4CIDR(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	for _, p := range db.v6 {
		if !include(p.ProvinceID) {
			continue
		}
		c, err := v6CIDR(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ExportCities 返回指定城市 code（文本，如 "330100"）的 IPv4 CIDR 列表。
func (db *DB) ExportCities(codes []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, text := range codes {
		code, ok := db.cityCodeByID[strings.TrimSpace(text)]
		if !ok {
			return nil, fmt.Errorf("未知城市 code：%s", text)
		}
		idx, ok := findCityIndex(db.cityIdx, code)
		if !ok {
			return nil, fmt.Errorf("城市 code 无可用 CIDR：%s", text)
		}
		start, end := int(idx.Offset), int(idx.Offset+idx.Count)
		if start < 0 || end > len(db.cityPfx) || start > end {
			return nil, fmt.Errorf("city index 越界 (code=%s)", text)
		}
		for _, p := range db.cityPfx[start:end] {
			c, err := cityV4CIDR(p)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

func findCityIndex(idx []cityIndexRecord, code uint32) (cityIndexRecord, bool) {
	for _, r := range idx {
		if r.Code == code {
			return r, true
		}
	}
	return cityIndexRecord{}, false
}
