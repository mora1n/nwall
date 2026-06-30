package geo

import "testing"

func TestDefaultLoads(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if len(db.Provinces()) == 0 {
		t.Fatal("应至少解析出若干省份")
	}
}

func TestExportAllNonEmpty(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	all, err := db.ExportProvinces("all", nil)
	if err != nil {
		t.Fatalf("ExportProvinces all: %v", err)
	}
	if len(all) < 1000 {
		t.Errorf("CN 全量 CIDR 数量异常偏少: %d", len(all))
	}
	// 校验全部为合法、已掩码的前缀。
	for i, p := range all {
		if !p.IsValid() {
			t.Fatalf("第 %d 个前缀非法: %v", i, p)
		}
		if p.Masked() != p {
			t.Fatalf("第 %d 个前缀未掩码: %v", i, p)
		}
		if i > 50 {
			break
		}
	}
}

func TestExportProvincesSubsetSmaller(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	all, _ := db.ExportProvinces("all", nil)
	provs := db.Provinces()
	one, err := db.ExportProvinces("provinces", provs[:1])
	if err != nil {
		t.Fatalf("ExportProvinces subset: %v", err)
	}
	if len(one) == 0 || len(one) >= len(all) {
		t.Errorf("单省 CIDR 数应在 (0, 全量) 之间，得 %d / %d", len(one), len(all))
	}
}

func TestExportProvincesUnknown(t *testing.T) {
	db, _ := Default()
	if _, err := db.ExportProvinces("provinces", []string{"火星省"}); err == nil {
		t.Error("未知省份应报错")
	}
}

func TestExportProvincesOff(t *testing.T) {
	db, _ := Default()
	got, err := db.ExportProvinces("off", nil)
	if err != nil || got != nil {
		t.Errorf("off 模式应返回空, got=%v err=%v", got, err)
	}
}
