package scanner

import "testing"

func TestPagesScannedParsesTheEngineSummary(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"Ringkasan: 7 halaman dipindai, 3 temuan, 0 peringatan", 7, true},
		{"halaman dipindai: 12", 12, true},
		{"crawl selesai: 7 halaman dipindai", 7, true},
		{"info\nPages scanned: 30 (limit 50)", 30, true},
		{"ringkasan: 5 pages", 5, true},
		{"peringatan: batas 500 halaman tercapai", 0, false},
		{"warning: 3 pages skipped", 0, false},
		{"tidak ada angka di sini", 0, false},
		{"", 0, false},
	} {
		got, ok := pagesScanned(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("pagesScanned(%q) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}
