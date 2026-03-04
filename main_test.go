package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/linode/linodego"
	"golang.org/x/oauth2"
)

// setEnvs sets env vars for the duration of a test and clears them on cleanup.
func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()
	for k, v := range envs {
		t.Setenv(k, v)
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	setEnvs(t, map[string]string{
		"DYNDNS_FOR_LINODE_API_TOKEN": "testtoken",
		"DYNDNS_FOR_LINODE_USERNAME":  "user",
		"DYNDNS_FOR_LINODE_PASSWORD":  "pass",
	})
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "testtoken" || cfg.Username != "user" || cfg.Password != "pass" || cfg.Port != "8080" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadConfig_CustomPort(t *testing.T) {
	setEnvs(t, map[string]string{
		"DYNDNS_FOR_LINODE_API_TOKEN": "testtoken",
		"DYNDNS_FOR_LINODE_USERNAME":  "user",
		"DYNDNS_FOR_LINODE_PASSWORD":  "pass",
		"DYNDNS_FOR_LINODE_PORT":      "9090",
	})
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("port = %q, want %q", cfg.Port, "9090")
	}
}

func TestLoadConfig_AllMissing(t *testing.T) {
	setEnvs(t, map[string]string{
		"DYNDNS_FOR_LINODE_API_TOKEN": "",
		"DYNDNS_FOR_LINODE_USERNAME":  "",
		"DYNDNS_FOR_LINODE_PASSWORD":  "",
	})
	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"API_TOKEN", "USERNAME", "PASSWORD"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing mention of %s", msg, want)
		}
	}
}

func TestLoadConfig_InvalidPort(t *testing.T) {
	setEnvs(t, map[string]string{
		"DYNDNS_FOR_LINODE_API_TOKEN": "testtoken",
		"DYNDNS_FOR_LINODE_USERNAME":  "user",
		"DYNDNS_FOR_LINODE_PASSWORD":  "pass",
		"DYNDNS_FOR_LINODE_PORT":      "99999",
	})
	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "PORT") {
		t.Errorf("error %q missing mention of PORT", err.Error())
	}
}

func TestParseUpdateRequest_Valid(t *testing.T) {
	rec, errStr := parseUpdateRequest("sub.example.com", "1.2.3.4", "")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if rec.Hostname != "sub.example.com" {
		t.Errorf("hostname = %q, want %q", rec.Hostname, "sub.example.com")
	}
	if !rec.IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("ip = %v, want 1.2.3.4", rec.IP)
	}
}

func TestParseUpdateRequest_MissingHostname(t *testing.T) {
	_, errStr := parseUpdateRequest("", "1.2.3.4", "")
	if errStr != "notfqdn" {
		t.Errorf("error = %q, want %q", errStr, "notfqdn")
	}
}

func TestParseUpdateRequest_InvalidIP(t *testing.T) {
	_, errStr := parseUpdateRequest("sub.example.com", "notanip", "")
	if errStr != "notfqdn" {
		t.Errorf("error = %q, want %q", errStr, "notfqdn")
	}
}

func TestParseUpdateRequest_MissingIPUsesRemoteAddr(t *testing.T) {
	rec, errStr := parseUpdateRequest("sub.example.com", "", "10.0.0.1:12345")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if !rec.IP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("ip = %v, want 10.0.0.1", rec.IP)
	}
}

func TestParseUpdateRequest_BareDomain(t *testing.T) {
	rec, errStr := parseUpdateRequest("example.com", "1.2.3.4", "")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if rec.Hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", rec.Hostname, "example.com")
	}
}

func TestParseUpdateRequest_NoDot(t *testing.T) {
	_, errStr := parseUpdateRequest("localhost", "1.2.3.4", "")
	if errStr != "notfqdn" {
		t.Errorf("error = %q, want %q", errStr, "notfqdn")
	}
}

func TestParseUpdateRequest_IPv6(t *testing.T) {
	rec, errStr := parseUpdateRequest("sub.example.com", "2001:db8::1", "")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if !rec.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("ip = %v, want 2001:db8::1", rec.IP)
	}
}

func TestSplitHostname(t *testing.T) {
	tests := []struct {
		input      string
		wantName   string
		wantDomain string
	}{
		{"sub.example.com", "sub", "example.com"},
		{"example.com", "", "example.com"},
		{"deep.sub.example.com", "deep", "sub.example.com"},
	}
	for _, tt := range tests {
		name, domain := splitHostname(tt.input)
		if name != tt.wantName || domain != tt.wantDomain {
			t.Errorf("splitHostname(%q) = (%q, %q), want (%q, %q)",
				tt.input, name, domain, tt.wantName, tt.wantDomain)
		}
	}
}

func TestUpdateDNS_Live(t *testing.T) {
	token := os.Getenv("DYNDNS_FOR_LINODE_API_TOKEN")
	if token == "" {
		t.Skip("DYNDNS_FOR_LINODE_API_TOKEN not set, skipping integration test")
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauth2Client := oauth2.NewClient(context.Background(), tokenSource)
	client := linodego.NewClient(oauth2Client)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	const hostname = "testdomain.aselia.me"
	const domainName = "aselia.me"
	const recordName = "testdomain"

	t.Cleanup(func() {
		domains, err := client.ListDomains(context.Background(), nil)
		if err != nil {
			t.Errorf("cleanup: failed to list domains: %v", err)
			return
		}
		for _, d := range domains {
			if d.Domain != domainName {
				continue
			}
			records, err := client.ListDomainRecords(context.Background(), d.ID, nil)
			if err != nil {
				t.Errorf("cleanup: failed to list records: %v", err)
				return
			}
			for _, r := range records {
				if r.Type == linodego.RecordTypeA && r.Name == recordName {
					if err := client.DeleteDomainRecord(context.Background(), d.ID, r.ID); err != nil {
						t.Errorf("cleanup: failed to delete record %d: %v", r.ID, err)
					} else {
						t.Logf("cleanup: deleted record %d (%s.%s)", r.ID, recordName, domainName)
					}
				}
			}
			return
		}
	})

	result, fatal := updateDNS(context.Background(), client, logger, UpdateRecord{
		Hostname: hostname,
		IP:       net.ParseIP("1.2.3.4"),
	})

	if fatal {
		t.Fatal("updateDNS reported fatal auth error")
	}
	if result != "good 1.2.3.4" && result != "nochg 1.2.3.4" {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestServerE2E_Live(t *testing.T) {
	token := os.Getenv("DYNDNS_FOR_LINODE_API_TOKEN")
	if token == "" {
		t.Skip("DYNDNS_FOR_LINODE_API_TOKEN not set, skipping E2E test")
	}

	// Set env vars for main().
	t.Setenv("DYNDNS_FOR_LINODE_API_TOKEN", token)
	t.Setenv("DYNDNS_FOR_LINODE_USERNAME", "testuser")
	t.Setenv("DYNDNS_FOR_LINODE_PASSWORD", "testpass")
	t.Setenv("DYNDNS_FOR_LINODE_PORT", "0")

	// Capture stderr so we can parse the "server listening" log line.
	origStderr := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = pw
	t.Cleanup(func() { os.Stderr = origStderr })

	// Run main() in a goroutine — it blocks on http.Serve.
	go main()

	// Read stderr lines until we find "server listening" with the port.
	var port int
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		line := scanner.Text()
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if msg, ok := entry["msg"].(string); ok && msg == "server listening" {
			if p, ok := entry["port"].(float64); ok {
				port = int(p)
				break
			}
		}
	}
	if port == 0 {
		t.Fatal("failed to discover server port from logs")
	}
	t.Logf("server listening on port %d", port)

	// Restore stderr so further logging goes to real stderr.
	os.Stderr = origStderr
	pw.Close()
	// Drain remaining pipe data to avoid blocking the writer goroutine.
	go io.Copy(io.Discard, pr)

	// Cleanup: delete the testdomain2 A record from aselia.me.
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauth2Client := oauth2.NewClient(context.Background(), tokenSource)
	linodeClient := linodego.NewClient(oauth2Client)

	t.Cleanup(func() {
		const domainName = "aselia.me"
		const recordName = "testdomain2"
		domains, err := linodeClient.ListDomains(context.Background(), nil)
		if err != nil {
			t.Errorf("cleanup: failed to list domains: %v", err)
			return
		}
		for _, d := range domains {
			if d.Domain != domainName {
				continue
			}
			records, err := linodeClient.ListDomainRecords(context.Background(), d.ID, nil)
			if err != nil {
				t.Errorf("cleanup: failed to list records: %v", err)
				return
			}
			for _, r := range records {
				if r.Type == linodego.RecordTypeA && r.Name == recordName {
					if err := linodeClient.DeleteDomainRecord(context.Background(), d.ID, r.ID); err != nil {
						t.Errorf("cleanup: failed to delete record %d: %v", r.ID, err)
					} else {
						t.Logf("cleanup: deleted record %d (%s.%s)", r.ID, recordName, domainName)
					}
				}
			}
			return
		}
	})

	// Send update request.
	url := fmt.Sprintf("http://localhost:%d/nic/update?hostname=testdomain2.aselia.me&myip=1.2.3.4", port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	t.Logf("response: status=%d body=%q", resp.StatusCode, bodyStr)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if bodyStr != "good 1.2.3.4" && bodyStr != "nochg 1.2.3.4" {
		t.Errorf("body = %q, want %q or %q", bodyStr, "good 1.2.3.4", "nochg 1.2.3.4")
	}

}
