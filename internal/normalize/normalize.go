// Package normalize provides URL, hostname, and path normalization functions
// used by the scope engine and all request-handling components.
// Normalization is critical for consistent scope matching and deduplication.
package normalize

import (
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Host normalizes a hostname for scope matching.
// - Lowercases ASCII characters
// - Converts internationalized domain names (IDN) to Punycode (ASCII)
// - Trims whitespace
// - Removes trailing dot
func Host(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")

	// Convert IDN to Punycode (ASCII).
	ascii, err := idna.ToASCII(host)
	if err == nil {
		host = ascii
	}

	return host
}

// URL normalizes a full URL for deduplication and comparison.
// - Lowercases scheme and host
// - Converts IDN host to Punycode
// - Sorts query parameters
// - Removes default ports (80 for http, 443 for https)
// - Removes fragment
// - Normalizes path (removes redundant slashes, resolves . and ..)
func URL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = Host(parsed.Host)

	// Remove default ports.
	if (parsed.Scheme == "http" && parsed.Port() == "80") ||
		(parsed.Scheme == "https" && parsed.Port() == "443") {
		parsed.Host = parsed.Hostname()
	}

	// Remove fragment.
	parsed.Fragment = ""

	// Sort query parameters for stable ordering.
	if parsed.RawQuery != "" {
		parsed.RawQuery = sortQuery(parsed.RawQuery)
	}

	// Normalize path: remove redundant slashes, resolve . and ..
	parsed.Path = cleanPath(parsed.Path)

	return parsed.String(), nil
}

// URLHost extracts and normalizes the host from a URL string.
func URLHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return Host(parsed.Hostname())
}

// Path normalizes a URL path.
// - Removes redundant slashes
// - Does NOT resolve . or .. (caller decides if appropriate)
// - Preserves trailing slash
func Path(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Collapse multiple slashes.
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	return path
}

// cleanPath resolves . and .. segments and removes redundant slashes.
func cleanPath(path string) string {
	if path == "" {
		return "/"
	}

	// Split, filter, and resolve.
	segments := strings.Split(path, "/")
	var cleaned []string
	for _, seg := range segments {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(cleaned) > 0 {
				cleaned = cleaned[:len(cleaned)-1]
			}
		default:
			cleaned = append(cleaned, seg)
		}
	}

	result := "/" + strings.Join(cleaned, "/")
	return result
}

// sortQuery normalizes query parameter ordering for deduplication.
// Simple approach: sort by key, preserve first value for duplicate keys.
func sortQuery(query string) string {
	if query == "" {
		return ""
	}

	pairs := strings.Split(query, "&")
	// Simple bubble-sort-like approach for small query strings.
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			ki := getKey(pairs[i])
			kj := getKey(pairs[j])
			if ki > kj {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}

	return strings.Join(pairs, "&")
}

func getKey(pair string) string {
	idx := strings.IndexByte(pair, '=')
	if idx < 0 {
		return pair
	}
	return pair[:idx]
}

// IsValidHostname performs basic hostname validation.
func IsValidHostname(host string) bool {
	if host == "" {
		return false
	}
	if len(host) > 253 {
		return false
	}

	// Check each label.
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				// Check for IDN characters.
				if r > 127 {
					continue
				}
				return false
			}
		}
	}
	return true
}

// IsIPLiteral checks if a string looks like an IPv4 or IPv6 address.
func IsIPLiteral(s string) bool {
	// Quick check: if it contains letters beyond a-f and colons, it's not an IP (except IPv6).
	s = strings.Trim(s, "[]")
	hasColon := strings.Contains(s, ":")
	hasDot := strings.Contains(s, ".")

	// IPv4: has dots, no colons.
	if hasDot && !hasColon {
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return false
		}
		for _, p := range parts {
			for _, r := range p {
				if r < '0' || r > '9' {
					return false
				}
			}
		}
		return true
	}

	// IPv6: has colons.
	if hasColon {
		for _, r := range s {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':' || r == '.') {
				return false
			}
		}
		return true
	}

	return false
}
