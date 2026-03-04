package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/linode/linodego"
	"golang.org/x/oauth2"
)

// config holds validated environment configuration.
type config struct {
	APIToken string
	Username string
	Password string
	Host     string
	Port     string
}

// loadConfig reads and validates all env vars, returning collected errors.
func loadConfig() (config, error) {
	var errs []string
	var cfg config

	cfg.APIToken = os.Getenv("DYNDNS_FOR_LINODE_API_TOKEN")
	if cfg.APIToken == "" {
		errs = append(errs, "DYNDNS_FOR_LINODE_API_TOKEN is required")
	}
	cfg.Username = os.Getenv("DYNDNS_FOR_LINODE_USERNAME")
	if cfg.Username == "" {
		errs = append(errs, "DYNDNS_FOR_LINODE_USERNAME is required")
	}
	cfg.Password = os.Getenv("DYNDNS_FOR_LINODE_PASSWORD")
	if cfg.Password == "" {
		errs = append(errs, "DYNDNS_FOR_LINODE_PASSWORD is required")
	}

	cfg.Host = "0.0.0.0"
	if h := os.Getenv("DYNDNS_FOR_LINODE_BIND_ADDRESS"); h != "" {
		if net.ParseIP(h) == nil {
			errs = append(errs, fmt.Sprintf("DYNDNS_FOR_LINODE_BIND_ADDRESS must be a valid IP address, got %q", h))
		} else {
			cfg.Host = h
		}
	}

	cfg.Port = "8080"
	if p := os.Getenv("DYNDNS_FOR_LINODE_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			errs = append(errs, fmt.Sprintf("DYNDNS_FOR_LINODE_PORT must be a valid port number (0-65535), got %q", p))
		} else {
			cfg.Port = p
		}
	}

	if len(errs) > 0 {
		return config{}, errors.New(strings.Join(errs, "; "))
	}
	return cfg, nil
}

// UpdateRecord holds validated update parameters.
type UpdateRecord struct {
	Hostname string // FQDN, e.g. "sub.example.com"
	IP       net.IP
}

// parseUpdateRequest validates raw query params and returns UpdateRecord or a DynDNS error string.
func parseUpdateRequest(hostname, myip, remoteAddr string) (UpdateRecord, string) {
	if hostname == "" {
		return UpdateRecord{}, "notfqdn"
	}

	// Hostname must contain at least one dot (bare domain like "example.com" is valid).
	if !strings.Contains(hostname, ".") {
		return UpdateRecord{}, "notfqdn"
	}

	var ip net.IP
	if myip != "" {
		ip = net.ParseIP(myip)
		if ip == nil {
			return UpdateRecord{}, "notfqdn"
		}
	} else {
		// Extract IP from remoteAddr (host:port format).
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			// remoteAddr might be just an IP without port.
			host = remoteAddr
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return UpdateRecord{}, "notfqdn"
		}
	}

	return UpdateRecord{Hostname: hostname, IP: ip}, ""
}

// splitHostname splits an FQDN into the record name and domain.
// e.g. "sub.example.com" → ("sub", "example.com")
// e.g. "example.com" → ("", "example.com")
func splitHostname(hostname string) (name, domain string) {
	parts := strings.SplitN(hostname, ".", 2)
	if len(parts) < 2 {
		return "", hostname
	}
	// Check if the second part contains a dot — if so, first part is the subdomain.
	if strings.Contains(parts[1], ".") {
		return parts[0], parts[1]
	}
	// Bare domain like "example.com".
	return "", hostname
}

// isLinodeAuthError returns true if the error is a 401 or 403 from the Linode API.
func isLinodeAuthError(err error) bool {
	var linodeErr *linodego.Error
	if errors.As(err, &linodeErr) {
		return linodeErr.Code == 401 || linodeErr.Code == 403
	}
	return false
}

// updateDNS performs the Linode API calls to update the DNS record.
// Returns a DynDNS response string like "good 1.2.3.4" and whether the error is fatal (token auth failure).
func updateDNS(ctx context.Context, client linodego.Client, logger *slog.Logger, req UpdateRecord) (string, bool) {
	name, domainName := splitHostname(req.Hostname)
	ipStr := req.IP.String()

	logger.Info("updating DNS", "hostname", req.Hostname, "name", name, "domain", domainName, "ip", ipStr)

	// Find the domain.
	domains, err := client.ListDomains(ctx, nil)
	if err != nil {
		logger.Error("failed to list domains", "error", err)
		return "dnserr", isLinodeAuthError(err)
	}

	var domainID int
	var found bool
	for _, d := range domains {
		if d.Domain == domainName {
			domainID = d.ID
			found = true
			break
		}
	}
	if !found {
		logger.Warn("domain not found", "domain", domainName)
		return "nohost", false
	}

	// Determine record type.
	recordType := linodego.RecordTypeA
	if req.IP.To4() == nil {
		recordType = linodego.RecordTypeAAAA
	}

	// Find existing record.
	records, err := client.ListDomainRecords(ctx, domainID, nil)
	if err != nil {
		logger.Error("failed to list domain records", "error", err, "domain_id", domainID)
		return "dnserr", isLinodeAuthError(err)
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			// Record exists — check if IP matches.
			if r.Target == ipStr {
				logger.Info("record unchanged", "record_id", r.ID)
				return fmt.Sprintf("nochg %s", ipStr), false
			}
			// Update existing record.
			_, err := client.UpdateDomainRecord(ctx, domainID, r.ID, linodego.DomainRecordUpdateOptions{
				Target: ipStr,
			})
			if err != nil {
				logger.Error("failed to update record", "error", err, "record_id", r.ID)
				return "dnserr", isLinodeAuthError(err)
			}
			logger.Info("record updated", "record_id", r.ID, "ip", ipStr)
			return fmt.Sprintf("good %s", ipStr), false
		}
	}

	// Record doesn't exist — create it.
	record, err := client.CreateDomainRecord(ctx, domainID, linodego.DomainRecordCreateOptions{
		Type:   recordType,
		Name:   name,
		Target: ipStr,
	})
	if err != nil {
		logger.Error("failed to create record", "error", err)
		return "dnserr", isLinodeAuthError(err)
	}
	logger.Info("record created", "record_id", record.ID, "ip", ipStr)
	return fmt.Sprintf("good %s", ipStr), false
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("configuration error", "details", err)
		os.Exit(1)
	}

	// Create linodego client.
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.APIToken})
	oauth2Client := oauth2.NewClient(context.Background(), tokenSource)
	client := linodego.NewClient(oauth2Client)

	// HTTP handler.
	mux := http.NewServeMux()

	checkAuth := func(r *http.Request) bool {
		u, p, ok := r.BasicAuth()
		return ok && u == cfg.Username && p == cfg.Password
	}

	mux.HandleFunc("/nic/update", func(w http.ResponseWriter, r *http.Request) {
		traceID := uuid.New().String()
		reqLogger := logger.With("trace_id", traceID, "path", r.URL.Path)

		w.Header().Set("Content-Type", "text/plain")

		if !checkAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="dyndns"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "badauth")
			reqLogger.Warn("authentication failed", "remote_addr", r.RemoteAddr)
			return
		}

		hostname := r.URL.Query().Get("hostname")
		myip := r.URL.Query().Get("myip")

		reqLogger.Info("update request", "hostname", hostname, "myip", myip, "remote_addr", r.RemoteAddr)

		rec, errStr := parseUpdateRequest(hostname, myip, r.RemoteAddr)
		if errStr != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, errStr)
			reqLogger.Warn("invalid request", "error", errStr)
			return
		}

		result, fatal := updateDNS(r.Context(), client, reqLogger, rec)

		switch {
		case strings.HasPrefix(result, "good"), strings.HasPrefix(result, "nochg"):
			w.WriteHeader(http.StatusOK)
		case result == "nohost":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		fmt.Fprint(w, result)

		if fatal {
			logger.Error("API token lacks required scope, shutting down")
			os.Exit(1)
		}
	})


	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server listening", "port", ln.Addr().(*net.TCPAddr).Port)
	if err := http.Serve(ln, mux); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
