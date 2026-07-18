package locker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Driver struct {
	lockerURL string
	client    *http.Client
}

func NewDriver(lockerURL string, client *http.Client) *Driver {
	return &Driver{lockerURL: lockerURL, client: client}
}

func (d *Driver) Fetch(ctx context.Context, source string) (io.ReadCloser, error) {
	// Parse locker://subjectId/entry/index
	path, ok := strings.CutPrefix(source, "locker://")
	if !ok {
		return nil, fmt.Errorf("invalid locker URI: %s", source)
	}

	// Validate path has at least subjectId/entry/index structure
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 3 || parts[1] != "entry" {
		return nil, fmt.Errorf("invalid locker URI format, expected locker://subjectId/entry/index: %s", source)
	}

	url := fmt.Sprintf("%s/ledgers/%s", d.lockerURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching from locker: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("locker returned status %d for %s", resp.StatusCode, source)
	}

	return resp.Body, nil
}
