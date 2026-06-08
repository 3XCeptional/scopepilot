package normalize

import (
	"strings"
	"testing"
)

func TestHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"App.Example.COM", "app.example.com"},
		{"APP.EXAMPLE.COM.", "app.example.com"},
		{"  spaced.example.com  ", "spaced.example.com"},
		{"münich.example.com", "xn--mnich-kva.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Host(tt.input)
			if got != tt.expected {
				t.Errorf("Host(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		err      bool
	}{
		{
			input:    "HTTPS://APP.EXAMPLE.COM/Path?A=1&B=2#frag",
			expected: "https://app.example.com/Path?A=1&B=2",
		},
		{
			input:    "http://app.example.com:80/path",
			expected: "http://app.example.com/path",
		},
		{
			input:    "https://app.example.com:443/path?a=1&b=2&a=3",
			expected: "https://app.example.com/path?a=1&a=3&b=2",
		},
		{
			input:    "https://app.example.com/path/../dir/./file",
			expected: "https://app.example.com/dir/file",
		},
		{
			input: "https://app.example.com/path%ZZinvalid",
			err:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := URL(tt.input)
			if (err != nil) != tt.err {
				t.Fatalf("URL() error = %v, wantErr = %v", err, tt.err)
			}
			if err == nil && got != tt.expected {
				t.Errorf("URL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"path", "/path"},
		{"//double//slash", "/double/slash"},
		{"/normal/path/", "/normal/path/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Path(tt.input)
			if got != tt.expected {
				t.Errorf("Path(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{"app.example.com", true},
		{"example.com", true},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
		{"", false},
		{strings.Repeat("a", 254), false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := IsValidHostname(tt.host)
			if got != tt.expected {
				t.Errorf("IsValidHostname(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

func TestIsIPLiteral(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1.2.3.4", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"[::1]", true},
		{"app.example.com", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsIPLiteral(tt.input)
			if got != tt.expected {
				t.Errorf("IsIPLiteral(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
