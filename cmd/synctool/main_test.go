package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIWhoamiAndDeviceListJSON(t *testing.T) {
	cfgDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{"--config", cfgDir, "--json", "device", "whoami"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("whoami exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var res struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal json: %v (%s)", err, stdout.String())
	}
	if res.Type != "result" {
		t.Fatalf("expected type=result, got %+v", res)
	}
	devID, _ := res.Data["device_id"].(string)
	if len(devID) != 32 {
		t.Fatalf("expected 32-hex device_id, got %q", devID)
	}
	// Ensure private seed never leaked into output
	if strings.Contains(stdout.String(), "master_seed") || strings.Contains(stdout.String(), "sign_sk") {
		t.Fatal("CLI output must never contain private keys or master seed")
	}

	// Verify exit code 2 on invalid relay URI
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--config", cfgDir, "--json", "init", "--stdin"}, strings.NewReader("synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843#k=0123456789abcdef0123456789abcdef\n"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for bare IP without pin, got %d stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "ERR_URI_INVALID") {
		t.Fatalf("expected ERR_URI_INVALID in json stdout, got %s", stdout.String())
	}
}

func TestCLIVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), version) || !strings.Contains(stdout.String(), commit) {
		t.Fatalf("version text failed code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// Both `synctool --json version` and `synctool version --json`
	for _, argv := range [][]string{{"--json", "version"}, {"version", "--json"}} {
		stdout.Reset()
		stderr.Reset()
		code = run(argv, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%s", argv, code, stderr.String())
		}
		var res struct {
			Type string `json:"type"`
			Data struct {
				Version string `json:"version"`
				Commit  string `json:"commit"`
			} `json:"data"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("%v unmarshal: %v (%s)", argv, err, stdout.String())
		}
		if res.Type != "result" || res.Data.Version != version || res.Data.Commit != commit {
			t.Fatalf("%v unexpected output: %+v", argv, res)
		}
	}
}
