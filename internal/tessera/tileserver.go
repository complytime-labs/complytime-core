// SPDX-License-Identifier: Apache-2.0

package tessera

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	flog "github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

// RegisterTilesAPI serves the Tessera POSIX storage directory as a standard
// tlog-tiles read API. Clients can fetch checkpoints, Merkle tree tiles,
// and entry bundles to compute and verify inclusion proofs offline.
//
// Routes are mounted at the Echo root (not under /api/) so they bypass auth
// middleware. Transparency log reads are public by design.
func RegisterTilesAPI(e *echo.Echo, storagePath string) {
	checkpointFS := http.FileServer(http.Dir(storagePath))
	tileFS := http.StripPrefix("/tile/",
		http.FileServer(http.Dir(filepath.Join(storagePath, "tile"))))

	e.GET("/checkpoint", echo.WrapHandler(
		noDirListing(cacheControl("no-cache", checkpointFS)),
	))

	e.GET("/tile/*", echo.WrapHandler(
		rejectTraversal(noDirListing(cacheControl("max-age=31536000, immutable", tileFS))),
	))
}

// RegisterWitnessedStatus adds an endpoint that reports whether a given
// log_index is covered by a witnessed (cosigned) checkpoint.
func RegisterWitnessedStatus(e *echo.Echo, storagePath string) {
	e.GET("/log/witnessed/:index", func(c echo.Context) error {
		indexStr := c.Param("index")
		index, err := strconv.ParseUint(indexStr, 10, 64)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid index: must be a non-negative integer",
			})
		}

		cpBytes, err := os.ReadFile(filepath.Join(storagePath, "checkpoint"))
		if err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{
				"error": "checkpoint not available",
			})
		}

		treeSize, cosigCount, err := parseCheckpoint(cpBytes)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("parse checkpoint: %v", err),
			})
		}

		witnessed := index < treeSize && cosigCount > 0

		return c.JSON(http.StatusOK, map[string]any{
			"index":         index,
			"witnessed":     witnessed,
			"tree_size":     treeSize,
			"witness_count": cosigCount,
		})
	})
}

func cacheControl(value string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", value)
		next.ServeHTTP(w, r)
	})
}

func rejectTraversal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseCheckpoint(raw []byte) (treeSize uint64, cosigCount int, err error) {
	var cp flog.Checkpoint
	if _, err := cp.Unmarshal(raw); err != nil {
		return 0, 0, fmt.Errorf("unmarshal checkpoint: %w", err)
	}

	n, err := note.Open(raw, note.VerifierList())
	if err != nil {
		var uve *note.UnverifiedNoteError
		if ok := errors.As(err, &uve); ok {
			n = uve.Note
		} else {
			return cp.Size, 0, nil
		}
	}

	totalSigs := len(n.Sigs) + len(n.UnverifiedSigs)
	if totalSigs > 1 {
		cosigCount = totalSigs - 1
	}
	return cp.Size, cosigCount, nil
}
