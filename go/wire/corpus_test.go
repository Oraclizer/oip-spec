package wire

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestReferenceDecodeCorpus checks the verdict of every row of the decode
// corpus that the Rust tests regenerate, including which error a Core with
// several defects receives.
func TestReferenceDecodeCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "interop", "wire-decode-mutations.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n")), "\n")
	if lines[0] != "id\tnesting\tcore\texpect" {
		t.Fatalf("corpus header %q", lines[0])
	}
	counts := map[string]int{}
	for _, line := range lines[1:] {
		columns := strings.Split(line, "\t")
		if len(columns) != 4 {
			t.Fatalf("corpus row %q", line)
		}
		nesting, err := strconv.Atoi(columns[1])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(columns[2])
		if err != nil {
			t.Fatal(err)
		}
		got := "OK"
		core, err := DecodeCore(raw)
		if err == nil {
			_, err = DecodeOperands(core, nesting)
		}
		if err != nil {
			got = err.Error()
		}
		if got != columns[3] {
			t.Errorf("%s: got %s, want %s", columns[0], got, columns[3])
		}
		counts[got]++
	}
	if len(lines)-1 < 31*20 || counts["INVALID_SOURCE"] == 0 {
		t.Fatalf("corpus too small or shallow: %v", counts)
	}
}
