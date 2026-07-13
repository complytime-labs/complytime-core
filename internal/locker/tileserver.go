package locker

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

// registerTileRoutes adds routes for serving Tessera checkpoint and tiles
// for a specific ledger. These routes match the tlog-tiles directory layout.
func registerTileRoutes(r chi.Router, locker *Locker) {
	// Checkpoint endpoint: /ledgers/{subjectId}/checkpoint
	r.Get("/ledgers/{subjectId}/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		subjectID := chi.URLParam(r, "subjectId")
		serveTesseraFile(w, r, locker, subjectID, "checkpoint")
	})

	// Tile endpoint: /ledgers/{subjectId}/tile/{level}/{index}/{width}
	r.Get("/ledgers/{subjectId}/tile/{level}/{index}/{width}", func(w http.ResponseWriter, r *http.Request) {
		subjectID := chi.URLParam(r, "subjectId")
		level := chi.URLParam(r, "level")
		index := chi.URLParam(r, "index")
		width := chi.URLParam(r, "width")

		tilePath := fmt.Sprintf("tile/%s/%s/%s", level, index, width)
		serveTesseraFile(w, r, locker, subjectID, tilePath)
	})
}

// serveTesseraFile serves a file from the ledger's Tessera storage directory.
func serveTesseraFile(w http.ResponseWriter, r *http.Request, locker *Locker, subjectID, filePath string) {
	ledger, ok := locker.GetLedger(subjectID)
	if !ok {
		http.Error(w, "ledger not found", http.StatusNotFound)
		return
	}

	// Construct the full file path
	fullPath := filepath.Join(ledger.TesseraStoragePath(), filePath)

	// Security: ensure the path doesn't escape the storage directory
	storagePath := ledger.TesseraStoragePath()
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(storagePath)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Check if file exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "error accessing file", http.StatusInternalServerError)
		return
	}

	// Don't serve directories
	if info.IsDir() {
		http.Error(w, "not a file", http.StatusBadRequest)
		return
	}

	// Serve the file with appropriate content type
	// Tessera files are text-based (checkpoint is signed note, tiles are entry bundles)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, fullPath)
}
