// Command fixture is a synthetic HTTP server used for testing ScopePilot.
// It serves static pages that exercise scope rules, redirects, path exclusions,
// rate limiting, and other proxy features.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	port := 8080
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	mux := http.NewServeMux()

	// Static pages
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/robots.txt", handleRobotsTXT)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/api/v1/users", handleAPIUsers)
	mux.HandleFunc("/api/v1/data", handleAPIData)

	// Redirects
	mux.HandleFunc("/redirect", handleRedirect)
	mux.HandleFunc("/redirect-loop", handleRedirectLoop)
	mux.HandleFunc("/redirect-external", handleRedirectExternal)

	// Scope test pages
	mux.HandleFunc("/scope/in-scope", handleInScope)
	mux.HandleFunc("/scope/out-of-scope", handleOutOfScope)
	mux.HandleFunc("/scope/excluded-path", handleExcludedPath)

	// Rate limit test
	mux.HandleFunc("/ratelimit/test", handleRateLimitTest)

	// Auth test
	mux.HandleFunc("/auth/basic", handleAuthBasic)

	// Large response
	mux.HandleFunc("/large", handleLarge)

	// Various status codes
	mux.HandleFunc("/status/404", handle404)
	mux.HandleFunc("/status/500", handle500)
	mux.HandleFunc("/status/403", handle403)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Fixture server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>ScopePilot Fixture</title></head>
<body>
<h1>ScopePilot Test Fixture</h1>
<p>This server provides synthetic pages for testing the ScopePilot proxy.</p>
<ul>
  <li><a href="/health">Health</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/api/v1/users">API Users</a></li>
  <li><a href="/redirect">Redirect</a></li>
  <li><a href="/scope/in-scope">In-Scope</a></li>
  <li><a href="/scope/out-of-scope">Out-of-Scope</a></li>
</ul>
</body>
</html>`)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","service":"scopepilot-fixture"}`)
}

func handleRobotsTXT(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /api/\n")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<html><body><h1>Login Page</h1><form><input type="text" name="user"><input type="password" name="pass"><button>Login</button></form></body></html>`)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<html><body><h1>Admin Panel</h1><p>Sensitive admin page for testing path exclusions.</p></body></html>`)
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"users":[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]}`)
}

func handleAPIData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"data":"synthetic-api-data"}`)
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("to")
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func handleRedirectLoop(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/redirect-loop", http.StatusFound)
}

func handleRedirectExternal(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://example.com/", http.StatusFound)
}

func handleInScope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<html><body><h1>In-Scope Page</h1><p>This page is within the authorized scope.</p></body></html>`)
}

func handleOutOfScope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<html><body><h1>Out-of-Scope Page</h1><p>This page is outside the authorized scope for testing denials.</p></body></html>`)
}

func handleExcludedPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<html><body><h1>Excluded Path</h1><p>This path should be excluded by path-prefix rules.</p></body></html>`)
}

func handleRateLimitTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"rate limit test endpoint"}`)
}

func handleAuthBasic(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "admin" || pass != "secret" {
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"authenticated"}`)
}

func handleLarge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	// Generate a ~100KB response
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	w.Write(data)
}

func handle404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `<html><body><h1>404 Not Found</h1></body></html>`)
}

func handle500(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, `<html><body><h1>500 Internal Server Error</h1></body></html>`)
}

func handle403(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<html><body><h1>403 Forbidden</h1></body></html>`)
}
