package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestComposeConfig(t *testing.T) {
	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman is not installed")
	}
	if out, err := exec.Command(podman, "info").CombinedOutput(); err != nil {
		t.Skipf("podman socket unavailable: %v\n%s", err, out)
	}
	root := repositoryRoot(t)
	cmd := exec.Command(podman, "compose", "config", "--quiet")
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SCOPEPILOT_MCP_API_KEY=integration-validation-only",
		"SCOPEPILOT_POSTGRES_PASSWORD=integration-validation-only",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("podman compose config failed: %v\n%s", err, output)
	}
}

func TestContainerBuilds(t *testing.T) {
	if os.Getenv("SCOPEPILOT_CONTAINER_TEST") != "1" {
		t.Skip("set SCOPEPILOT_CONTAINER_TEST=1 to build container images")
	}
	if runtime.GOARCH != "arm64" {
		t.Skip("container images are currently pinned for linux/arm64")
	}
	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman is not installed")
	}
	root := repositoryRoot(t)
	builds := []struct {
		name string
		file string
	}{
		{name: "scopepilot", file: "containers/scopepilot/Containerfile"},
		{name: "fixture", file: "containers/fixture/Containerfile"},
		{name: "wireguard", file: "containers/wireguard/Containerfile"},
	}
	for _, build := range builds {
		t.Run(build.name, func(t *testing.T) {
			cmd := exec.Command(
				podman, "build",
				"--platform=linux/arm64",
				"-t", "localhost/scopepilot-integration-"+build.name+":test",
				"-f", build.file,
				".",
			)
			cmd.Dir = root
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("container build failed: %v\n%s", err, output)
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
