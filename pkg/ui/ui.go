package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

// Handler returns an http.Handler that serves the embedded UI.
// Mount it with http.StripPrefix("/ui", ui.Handler()) so that
// requests arrive with paths like "/" or "/index.html".
func Handler() http.Handler {
	subFS, _ := fs.Sub(staticFiles, "static")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Normalize path
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to read the file
		data, err := fs.ReadFile(subFS, path)
		if err != nil {
			// SPA fallback: serve index.html for unknown paths
			data, err = fs.ReadFile(subFS, "index.html")
			if err != nil {
				http.Error(w, "UI not found", http.StatusNotFound)
				return
			}
			path = "index.html"
		}

		// Set content type
		switch {
		case strings.HasSuffix(path, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case strings.HasSuffix(path, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(path, ".js"):
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		case strings.HasSuffix(path, ".json"):
			w.Header().Set("Content-Type", "application/json")
		case strings.HasSuffix(path, ".png"):
			w.Header().Set("Content-Type", "image/png")
		case strings.HasSuffix(path, ".svg"):
			w.Header().Set("Content-Type", "image/svg+xml")
		}

		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})
}
