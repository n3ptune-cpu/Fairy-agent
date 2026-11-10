package collect

import (
	"os"
	"testing"
	"time"
)

func TestAMDGPUNone(t *testing.T) {
	if NewAMDGPU(t.TempDir(), time.Second) != nil {
		t.Fatal("no cards = no reader")
	}
}

func TestReadAMDGPUBadValues(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) {
		t.Helper()
		if err := writeFile(dir+"/"+name, v); err != nil {
			t.Fatal(err)
		}
	}
	write("gpu_busy_percent", "250")
	write("mem_info_vram_used", "900")
	write("mem_info_vram_total", "100") // used > total
	write("product_name", "bad\x01name")
	write("device", "zz")
	g := ReadAMDGPU(dir, 0)
	if g.UtilPercent != nil || g.VRAMUsed != nil || g.Name != "AMD Radeon (amdgpu)" {
		t.Fatalf("%+v", g)
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s+"\n"), 0o644) }
