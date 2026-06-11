package adapter

import (
	"strings"
	"testing"
)

func TestBBOTArgs(t *testing.T) {
	targets := []string{"example.com", "test.com"}
	proxyURL := "http://127.0.0.1:8443"

	args := bbotArgs(targets, proxyURL)

	// Verify targets
	foundTargets := false
	for _, a := range args {
		if a == "example.com,test.com" {
			foundTargets = true
			break
		}
	}
	if !foundTargets {
		t.Error("bbotArgs: targets not found in args")
	}

	// Verify modern flags (not removed v1.x flags)
	for _, bad := range []string{"--passive-only", "--no-dns", "--no-www"} {
		for _, a := range args {
			if a == bad {
				t.Errorf("bbotArgs: deprecated flag %s should not be present", bad)
			}
		}
	}

	// Verify modern flags present
	hasRFPassive := false
	hasJSON := false
	hasYes := false
	for _, a := range args {
		switch a {
		case "-rf":
			hasRFPassive = true
		case "-om":
			hasJSON = true
		case "-y":
			hasYes = true
		}
	}
	if !hasRFPassive {
		t.Error("bbotArgs: missing -rf flag for module filtering")
	}
	if !hasJSON {
		t.Error("bbotArgs: missing output module flag")
	}
	if !hasYes {
		t.Error("bbotArgs: missing -y non-interactive flag")
	}
}

func TestNucleiArgs(t *testing.T) {
	templateDir := "/templates"
	targets := []string{"example.com", "test.com"}

	args := nucleiArgs(templateDir, targets)

	// Verify -jsonl present (not deprecated -json)
	hasJSONL := false
	hasDeprecatedJSON := false
	for _, a := range args {
		if a == "-jsonl" {
			hasJSONL = true
		}
		if a == "-json" {
			hasDeprecatedJSON = true
		}
	}
	if !hasJSONL {
		t.Error("nucleiArgs: missing -jsonl flag (v3.x+)")
	}
	if hasDeprecatedJSON {
		t.Error("nucleiArgs: deprecated -json flag should not be present")
	}

	// Verify template dir
	foundTemplate := false
	for _, a := range args {
		if a == templateDir {
			foundTemplate = true
			break
		}
	}
	if !foundTemplate {
		t.Error("nucleiArgs: template directory not found in args")
	}

	// Verify targets present
	for _, target := range targets {
		found := false
		for _, a := range args {
			if a == target {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("nucleiArgs: target %q not found", target)
		}
	}
}

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"2.14.0", 2},
		{"3.0.0", 3},
		{"1.5.2", 1},
		{"BBOT v2.14.0", 2},
		{"nuclei 3.2.1", 3},
		{"garbage", 0},
		{"", 0},
		{"0.1.0", 0},
	}
	for _, tc := range tests {
		got := parseMajorVersion(tc.input)
		if got != tc.want {
			t.Errorf("parseMajorVersion(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestBBOTArgsNoDeprecatedFlags(t *testing.T) {
	args := bbotArgs([]string{"x.com"}, "http://proxy:8080")
	argStr := strings.Join(args, " ")
	deprecated := []string{"--passive-only", "--no-dns", "--no-www"}
	for _, d := range deprecated {
		if strings.Contains(argStr, d) {
			t.Errorf("bbot args contain deprecated flag %q: %s", d, args)
		}
	}
}

func TestNucleiArgsNoDeprecatedFlags(t *testing.T) {
	args := nucleiArgs("/templates", []string{"x.com"})
	argStr := strings.Join(args, " ")
	if strings.Contains(argStr, "-json ") {
		t.Errorf("nuclei args contain deprecated -json flag: %s", args)
	}
}
