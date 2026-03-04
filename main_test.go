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

func TestFindDomain(t *testing.T) {
	domains := []linodego.Domain{
		{ID: 1, Domain: "example.com"},
		{ID: 2, Domain: "samuels.xyz"},
		{ID: 3, Domain: "sub.example.com"},
	}

	tests := []struct {
		hostname     string
		wantName     string
		wantDomainID int
		wantFound    bool
	}{
		{"sub.example.com", "", 3, true},              // exact match on sub.example.com domain
		{"example.com", "", 1, true},                   // bare domain
		{"foo.example.com", "foo", 1, true},            // subdomain of example.com
		{"dvr.33m.samuels.xyz", "dvr.33m", 2, true},   // multi-level subdomain
		{"unknown.org", "", 0, false},                  // no match
		{"deep.sub.example.com", "deep", 3, true},     // prefers longer domain match
	}
	for _, tt := range tests {
		name, domainID, found := findDomain(tt.hostname, domains)
		if found != tt.wantFound || domainID != tt.wantDomainID || name != tt.wantName {
			t.Errorf("findDomain(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tt.hostname, name, domainID, found, tt.wantName, tt.wantDomainID, tt.wantFound)
		}
	}
}

func TestParseUpdateRequests_Single(t *testing.T) {
	recs, errStr := parseUpdateRequests("sub.example.com", "1.2.3.4", "")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Hostname != "sub.example.com" {
		t.Errorf("hostname = %q, want %q", recs[0].Hostname, "sub.example.com")
	}
}

func TestParseUpdateRequests_CommaSeparated(t *testing.T) {
	recs, errStr := parseUpdateRequests("a.example.com,b.example.com", "1.2.3.4", "")
	if errStr != "" {
		t.Fatalf("unexpected error: %s", errStr)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Hostname != "a.example.com" {
		t.Errorf("recs[0].Hostname = %q, want %q", recs[0].Hostname, "a.example.com")
	}
	if recs[1].Hostname != "b.example.com" {
		t.Errorf("recs[1].Hostname = %q, want %q", recs[1].Hostname, "b.example.com")
	}
}

func TestParseUpdateRequests_InvalidInList(t *testing.T) {
	_, errStr := parseUpdateRequests("a.example.com,localhost", "1.2.3.4", "")
	if errStr != "notfqdn" {
		t.Errorf("error = %q, want %q", errStr, "notfqdn")
	}
}

// deleteTestRecords finds the domain and deletes any A records matching the given names.
func deleteTestRecords(t *testing.T, client linodego.Client, domainName string, recordNames []string) {
	t.Helper()
	domains, err := client.ListDomains(context.Background(), nil)
	if err != nil {
		t.Fatalf("deleteTestRecords: failed to list domains: %v", err)
	}
	for _, d := range domains {
		if d.Domain != domainName {
			continue
		}
		records, err := client.ListDomainRecords(context.Background(), d.ID, nil)
		if err != nil {
			t.Fatalf("deleteTestRecords: failed to list records: %v", err)
		}
		nameSet := make(map[string]bool, len(recordNames))
		for _, n := range recordNames {
			nameSet[n] = true
		}
		for _, r := range records {
			if r.Type == linodego.RecordTypeA && nameSet[r.Name] {
				if err := client.DeleteDomainRecord(context.Background(), d.ID, r.ID); err != nil {
					t.Fatalf("deleteTestRecords: failed to delete record %d: %v", r.ID, err)
				}
				t.Logf("deleteTestRecords: deleted record %d (%s.%s)", r.ID, r.Name, domainName)
			}
		}
		return
	}
}

// assertLinodeRecord queries the Linode API and asserts an A record exists with the expected IP.
func assertLinodeRecord(t *testing.T, client linodego.Client, domainName, recordName, expectedIP string) {
	t.Helper()
	domains, err := client.ListDomains(context.Background(), nil)
	if err != nil {
		t.Fatalf("assertLinodeRecord: failed to list domains: %v", err)
	}
	for _, d := range domains {
		if d.Domain != domainName {
			continue
		}
		records, err := client.ListDomainRecords(context.Background(), d.ID, nil)
		if err != nil {
			t.Fatalf("assertLinodeRecord: failed to list records: %v", err)
		}
		for _, r := range records {
			if r.Type == linodego.RecordTypeA && r.Name == recordName {
				if r.Target != expectedIP {
					t.Errorf("assertLinodeRecord: %s.%s target = %q, want %q", recordName, domainName, r.Target, expectedIP)
				}
				return
			}
		}
		t.Errorf("assertLinodeRecord: A record %s.%s not found", recordName, domainName)
		return
	}
	t.Errorf("assertLinodeRecord: domain %s not found", domainName)
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

	const domainName = "aselia.me"
	recordNames := []string{"testdomain0", "testdomain1.testsubdomain"}

	// Pre-test cleanup: delete any leftover records.
	deleteTestRecords(t, client, domainName, recordNames)

	// Post-test cleanup.
	t.Cleanup(func() {
		deleteTestRecords(t, client, domainName, recordNames)
	})

	// Parse multi-hostname request (second hostname has deeper subdomain).
	recs, errStr := parseUpdateRequests("testdomain0.aselia.me,testdomain1.testsubdomain.aselia.me", "1.2.3.4", "")
	if errStr != "" {
		t.Fatalf("parseUpdateRequests: %s", errStr)
	}

	// First update: set both to 1.2.3.4.
	for _, rec := range recs {
		result, fatal := updateDNS(context.Background(), client, logger, rec)
		if fatal {
			t.Fatal("updateDNS reported fatal auth error")
		}
		if result != "good 1.2.3.4" && result != "nochg 1.2.3.4" {
			t.Errorf("unexpected result for %s: %q", rec.Hostname, result)
		}
	}

	// Verify both records via API.
	for _, name := range recordNames {
		assertLinodeRecord(t, client, domainName, name, "1.2.3.4")
	}

	// Second update: change both to 5.6.7.8.
	recs2, errStr := parseUpdateRequests("testdomain0.aselia.me,testdomain1.testsubdomain.aselia.me", "5.6.7.8", "")
	if errStr != "" {
		t.Fatalf("parseUpdateRequests: %s", errStr)
	}
	for _, rec := range recs2 {
		result, fatal := updateDNS(context.Background(), client, logger, rec)
		if fatal {
			t.Fatal("updateDNS reported fatal auth error")
		}
		if result != "good 5.6.7.8" && result != "nochg 5.6.7.8" {
			t.Errorf("unexpected result for %s: %q", rec.Hostname, result)
		}
	}

	// Verify both records updated.
	for _, name := range recordNames {
		assertLinodeRecord(t, client, domainName, name, "5.6.7.8")
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

	// Create Linode client for verification.
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauth2Client := oauth2.NewClient(context.Background(), tokenSource)
	linodeClient := linodego.NewClient(oauth2Client)

	const domainName = "aselia.me"
	recordNames := []string{"testdomain2", "testdomain3.testsubdomain"}

	// Pre-test cleanup.
	deleteTestRecords(t, linodeClient, domainName, recordNames)

	// Post-test cleanup.
	t.Cleanup(func() {
		deleteTestRecords(t, linodeClient, domainName, recordNames)
	})

	// First request: update both hostnames to 1.2.3.4 (second has deeper subdomain).
	url1 := fmt.Sprintf("http://localhost:%d/nic/update?hostname=testdomain2.aselia.me,testdomain3.testsubdomain.aselia.me&myip=1.2.3.4", port)
	req1, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req1.SetBasicAuth("testuser", "testpass")

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	bodyStr1 := string(body1)
	t.Logf("response 1: status=%d body=%q", resp1.StatusCode, bodyStr1)

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp1.StatusCode, http.StatusOK)
	}

	// Expect two lines, each good/nochg.
	lines1 := strings.Split(bodyStr1, "\n")
	if len(lines1) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %q", len(lines1), bodyStr1)
	}
	for i, line := range lines1 {
		if !strings.HasPrefix(line, "good ") && !strings.HasPrefix(line, "nochg ") {
			t.Errorf("line %d = %q, want good/nochg prefix", i, line)
		}
	}

	// Verify both records via Linode API.
	for _, name := range recordNames {
		assertLinodeRecord(t, linodeClient, domainName, name, "1.2.3.4")
	}

	// Second request: update both to 5.6.7.8.
	url2 := fmt.Sprintf("http://localhost:%d/nic/update?hostname=testdomain2.aselia.me,testdomain3.testsubdomain.aselia.me&myip=5.6.7.8", port)
	req2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req2.SetBasicAuth("testuser", "testpass")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	bodyStr2 := string(body2)
	t.Logf("response 2: status=%d body=%q", resp2.StatusCode, bodyStr2)

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	lines2 := strings.Split(bodyStr2, "\n")
	if len(lines2) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %q", len(lines2), bodyStr2)
	}
	for i, line := range lines2 {
		if !strings.HasPrefix(line, "good ") && !strings.HasPrefix(line, "nochg ") {
			t.Errorf("line %d = %q, want good/nochg prefix", i, line)
		}
	}

	// Verify both records updated.
	for _, name := range recordNames {
		assertLinodeRecord(t, linodeClient, domainName, name, "5.6.7.8")
	}
}
