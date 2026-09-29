package pbs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ticketLifetime is how long a PBS auth ticket is valid; we renew a margin
// earlier so long operations never start with an almost-expired ticket.
const (
	ticketLifetime    = 2 * time.Hour
	ticketRenewMargin = 15 * time.Minute
)

// Client holds connection settings and (for password auth) the cached
// ticket. Safe for concurrent use.
type Client struct {
	cfg      Config
	crypt    *cryptState // nil when Config.Crypt is nil
	addr     string      // host:port
	tlsConf  *tls.Config
	restHTTP *http.Client // HTTP/1.1 client for the regular API (ticket login)

	mu         sync.Mutex
	ticket     string
	csrf       string
	ticketTime time.Time
}

// NewClient validates the configuration. No connection is made until
// StartBackup (or the first ticket login).
func NewClient(cfg Config) (*Client, error) {
	if cfg.Auth == nil && cfg.DialSession == nil {
		return nil, fmt.Errorf("pbs: Config.Auth is required")
	}
	if cfg.Datastore == "" && cfg.DialSession == nil {
		return nil, fmt.Errorf("pbs: Config.Datastore is required")
	}
	if cfg.Workers < 0 {
		return nil, fmt.Errorf("pbs: negative worker count %d", cfg.Workers)
	}
	if cfg.ChunkSizeAvg != 0 && cfg.ChunkSizeAvg&(cfg.ChunkSizeAvg-1) != 0 {
		return nil, fmt.Errorf("pbs: ChunkSizeAvg %d is not a power of two", cfg.ChunkSizeAvg)
	}
	var crypt *cryptState
	if cfg.Crypt != nil {
		var err error
		if crypt, err = newCryptState(cfg.Crypt); err != nil {
			return nil, err
		}
	}

	// With DialSession the address only labels requests on the session
	// connection (the :authority pseudo-header); BaseURL may be omitted.
	addr := "localhost:8007"
	if cfg.BaseURL != "" || cfg.DialSession == nil {
		var err error
		if addr, err = hostPort(cfg.BaseURL); err != nil {
			return nil, err
		}
	}
  
	tlsConf, err := newTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
  
	return &Client{
		cfg:     cfg,
		crypt:   crypt,
		addr:    addr,
		tlsConf: tlsConf,
		restHTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: false,
			},
		},
	}, nil
}

// authHeaders adds authentication to h. For password auth this logs in (or
// renews) as needed; mutating adds the CSRF token required for non-GET
// requests on the regular API.
func (c *Client) authHeaders(ctx context.Context, h http.Header, mutating bool) error {
	switch a := c.cfg.Auth.(type) {
	case TokenAuth:
		h.Set("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", a.AuthID, a.Secret))
		return nil
	case PasswordAuth:
		ticket, csrf, err := c.ensureTicket(ctx, a)
		if err != nil {
			return err
		}
		h.Set("Cookie", "PBSAuthCookie="+url.QueryEscape(ticket))
		if mutating {
			h.Set("CSRFPreventionToken", csrf)
		}
		return nil
	}
	return fmt.Errorf("pbs: unsupported auth type %T", c.cfg.Auth)
}

func (c *Client) ensureTicket(ctx context.Context, a PasswordAuth) (ticket, csrf string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ticket != "" && time.Since(c.ticketTime) < ticketLifetime-ticketRenewMargin {
		return c.ticket, c.csrf, nil
	}

	form := url.Values{
		"username": {a.userID()},
		"password": {a.Password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.addr+"/api2/json/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("pbs: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.restHTTP.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("pbs: ticket login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", "", statusError("ticket login", resp.Status, resp.StatusCode, body)
	}

	var parsed struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", "", fmt.Errorf("pbs: ticket login: decoding response: %w", err)
	}
	if parsed.Data.Ticket == "" {
		return "", "", fmt.Errorf("pbs: ticket login: response carries no ticket")
	}
	c.ticket, c.csrf, c.ticketTime = parsed.Data.Ticket, parsed.Data.CSRF, time.Now()
	return c.ticket, c.csrf, nil
}
