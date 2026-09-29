package pbs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// SnapshotInfo is one entry of ListSnapshots.
type SnapshotInfo struct {
	Ref       SnapshotRef
	Size      uint64 // as the server reports it
	Files     []string
	Protected bool
}

// ListSnapshots returns one backup group's snapshots, newest first.
// backupType "" means "host". The token needs Datastore.Audit or
// Datastore.Backup.
func (c *Client) ListSnapshots(ctx context.Context, backupType, backupID string) ([]SnapshotInfo, error) {
	if c.cfg.Auth == nil || c.cfg.Datastore == "" || c.cfg.BaseURL == "" {
		return nil, fmt.Errorf("pbs: listing snapshots requires Config.BaseURL, Auth and Datastore")
	}
	if backupType == "" {
		backupType = "host"
	}
	if backupID == "" {
		return nil, fmt.Errorf("pbs: listing snapshots requires a backup id")
	}

	query := url.Values{
		"backup-type": {backupType},
		"backup-id":   {backupID},
	}
	if c.cfg.Namespace != "" {
		query.Set("ns", c.cfg.Namespace)
	}
	u := &url.URL{
		Scheme:   "https",
		Host:     c.addr,
		Path:     "/api2/json/admin/datastore/" + url.PathEscape(c.cfg.Datastore) + "/snapshots",
		RawQuery: query.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("pbs: %w", err)
	}
	if err := c.authHeaders(ctx, req.Header, false); err != nil {
		return nil, err
	}

	resp, err := c.restHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pbs: listing snapshots: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("pbs: listing snapshots: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError("listing snapshots", resp.Status, resp.StatusCode, body)
	}

	var parsed struct {
		Data []struct {
			BackupType string `json:"backup-type"`
			BackupID   string `json:"backup-id"`
			BackupTime int64  `json:"backup-time"`
			Size       uint64 `json:"size"`
			Protected  bool   `json:"protected"`
			Files      []struct {
				Filename string `json:"filename"`
			} `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("pbs: listing snapshots: decoding response: %w", err)
	}

	out := make([]SnapshotInfo, 0, len(parsed.Data))
	for _, d := range parsed.Data {
		// Not every server implementation honours the query filter.
		if d.BackupType != backupType || d.BackupID != backupID {
			continue
		}
		info := SnapshotInfo{
			Ref:       SnapshotRef{Type: d.BackupType, ID: d.BackupID, Time: time.Unix(d.BackupTime, 0)},
			Size:      d.Size,
			Protected: d.Protected,
		}
		for _, f := range d.Files {
			info.Files = append(info.Files, f.Filename)
		}
		out = append(out, info)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ref.Time.After(out[j].Ref.Time) })
	return out, nil
}
