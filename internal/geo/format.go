// Package geo 解析内嵌的 CN 地理资产（省/市 CIDR），供入站/出站白名单导出 nft 元素。
// 资产二进制格式使用 magic PFGE / PFCI，解析逻辑保持向后兼容。
package geo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
)

const (
	geoAssetMagic   = "PFGE"
	geoAssetVersion = 2
	geoHeaderSize   = 20

	cityAssetMagic   = "PFCI"
	cityAssetVersion = 1
	cityHeaderSize   = 20
	cityIndexSize    = 12
	cityPrefixSize   = 8
)

type geoHeader struct {
	Magic         [4]byte
	Version       uint16
	IPVersion     uint16
	BucketCount   uint32
	SegmentCount  uint32
	ProvinceCount uint32
}

type prefixV4 struct {
	PrefixLen  uint32
	Addr       uint32
	ProvinceID uint16
}

type prefixV6 struct {
	PrefixLen  uint32
	Addr       [16]byte
	ProvinceID uint16
}

type cityHeader struct {
	Magic       [4]byte
	Version     uint16
	IPVersion   uint16
	IndexCount  uint32
	PrefixCount uint32
	Reserved    uint32
}

type cityIndexRecord struct {
	Code   uint32
	Offset uint32
	Count  uint32
}

type cityPrefixV4 struct {
	PrefixLen uint32
	Addr      uint32
}

type provinceEntry struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Hidden bool   `json:"hidden,omitempty"`
}

type geoMeta struct {
	Provinces []provinceEntry `json:"provinces"`
}

type cityMeta struct {
	Provinces []struct {
		Name   string `json:"name"`
		Code   string `json:"code"`
		Cities []struct {
			Name string `json:"name"`
			Code string `json:"code"`
		} `json:"cities"`
	} `json:"provinces"`
}

func parseGeoV4(content []byte) ([]prefixV4, error) {
	if len(content) < geoHeaderSize {
		return nil, fmt.Errorf("geo v4 资产过短")
	}
	var h geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &h); err != nil {
		return nil, fmt.Errorf("解析 geo v4 header 失败: %w", err)
	}
	if string(h.Magic[:]) != geoAssetMagic {
		return nil, fmt.Errorf("geo v4 magic 不匹配")
	}
	if h.Version != geoAssetVersion {
		return nil, fmt.Errorf("geo v4 资产版本=%d，不支持", h.Version)
	}
	if h.IPVersion != 4 {
		return nil, fmt.Errorf("geo v4 资产 ip_version=%d", h.IPVersion)
	}
	off := geoHeaderSize
	out := make([]prefixV4, int(h.SegmentCount))
	if len(content) < off+len(out)*12 {
		return nil, fmt.Errorf("geo v4 prefix 数据截断")
	}
	for i := range out {
		out[i].PrefixLen = binary.LittleEndian.Uint32(content[off:])
		out[i].Addr = binary.LittleEndian.Uint32(content[off+4:])
		out[i].ProvinceID = binary.LittleEndian.Uint16(content[off+8:])
		off += 12
	}
	return out, nil
}

func parseGeoV6(content []byte) ([]prefixV6, error) {
	if len(content) < geoHeaderSize {
		return nil, fmt.Errorf("geo v6 资产过短")
	}
	var h geoHeader
	if err := binary.Read(bytes.NewReader(content[:geoHeaderSize]), binary.LittleEndian, &h); err != nil {
		return nil, fmt.Errorf("解析 geo v6 header 失败: %w", err)
	}
	if string(h.Magic[:]) != geoAssetMagic {
		return nil, fmt.Errorf("geo v6 magic 不匹配")
	}
	if h.Version != geoAssetVersion {
		return nil, fmt.Errorf("geo v6 资产版本=%d，不支持", h.Version)
	}
	if h.IPVersion != 6 {
		return nil, fmt.Errorf("geo v6 资产 ip_version=%d", h.IPVersion)
	}
	off := geoHeaderSize
	out := make([]prefixV6, int(h.SegmentCount))
	if len(content) < off+len(out)*24 {
		return nil, fmt.Errorf("geo v6 prefix 数据截断")
	}
	for i := range out {
		out[i].PrefixLen = binary.LittleEndian.Uint32(content[off:])
		copy(out[i].Addr[:], content[off+4:off+20])
		out[i].ProvinceID = binary.LittleEndian.Uint16(content[off+20:])
		off += 24
	}
	return out, nil
}

func parseCityV4(content []byte) ([]cityIndexRecord, []cityPrefixV4, error) {
	if len(content) < cityHeaderSize {
		return nil, nil, fmt.Errorf("city v4 资产过短")
	}
	var h cityHeader
	if err := binary.Read(bytes.NewReader(content[:cityHeaderSize]), binary.LittleEndian, &h); err != nil {
		return nil, nil, fmt.Errorf("解析 city v4 header 失败: %w", err)
	}
	if string(h.Magic[:]) != cityAssetMagic {
		return nil, nil, fmt.Errorf("city v4 magic 不匹配")
	}
	if h.Version != cityAssetVersion {
		return nil, nil, fmt.Errorf("city v4 资产版本=%d，不支持", h.Version)
	}
	indexBytes := int(h.IndexCount) * cityIndexSize
	prefixBytes := int(h.PrefixCount) * cityPrefixSize
	if len(content) < cityHeaderSize+indexBytes+prefixBytes {
		return nil, nil, fmt.Errorf("city v4 资产数据截断")
	}
	idx := make([]cityIndexRecord, int(h.IndexCount))
	off := cityHeaderSize
	for i := range idx {
		idx[i].Code = binary.LittleEndian.Uint32(content[off:])
		idx[i].Offset = binary.LittleEndian.Uint32(content[off+4:])
		idx[i].Count = binary.LittleEndian.Uint32(content[off+8:])
		if idx[i].Offset+idx[i].Count > h.PrefixCount {
			return nil, nil, fmt.Errorf("city v4 index 越界 (code=%d)", idx[i].Code)
		}
		off += cityIndexSize
	}
	pfx := make([]cityPrefixV4, int(h.PrefixCount))
	for i := range pfx {
		pfx[i].PrefixLen = binary.LittleEndian.Uint32(content[off:])
		pfx[i].Addr = binary.LittleEndian.Uint32(content[off+4:])
		off += cityPrefixSize
	}
	return idx, pfx, nil
}

func v4CIDR(p prefixV4) (netip.Prefix, error) {
	if p.PrefixLen > 32 {
		return netip.Prefix{}, fmt.Errorf("无效 geo v4 prefix_len：%d", p.PrefixLen)
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], p.Addr)
	return netip.PrefixFrom(netip.AddrFrom4(raw), int(p.PrefixLen)).Masked(), nil
}

func v6CIDR(p prefixV6) (netip.Prefix, error) {
	if p.PrefixLen > 128 {
		return netip.Prefix{}, fmt.Errorf("无效 geo v6 prefix_len：%d", p.PrefixLen)
	}
	return netip.PrefixFrom(netip.AddrFrom16(p.Addr), int(p.PrefixLen)).Masked(), nil
}

func cityV4CIDR(p cityPrefixV4) (netip.Prefix, error) {
	if p.PrefixLen > 32 {
		return netip.Prefix{}, fmt.Errorf("无效 city v4 prefix_len：%d", p.PrefixLen)
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], p.Addr)
	return netip.PrefixFrom(netip.AddrFrom4(raw), int(p.PrefixLen)).Masked(), nil
}

func parseGeoMeta(content []byte) (geoMeta, error) {
	var m geoMeta
	if err := json.Unmarshal(content, &m); err != nil {
		return geoMeta{}, fmt.Errorf("解析 geo 元数据失败: %w", err)
	}
	return m, nil
}

func parseCityMeta(content []byte) (cityMeta, error) {
	var m cityMeta
	if err := json.Unmarshal(content, &m); err != nil {
		return cityMeta{}, fmt.Errorf("解析 city 元数据失败: %w", err)
	}
	return m, nil
}
