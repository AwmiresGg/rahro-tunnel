// Package web embeds the Rahro panel's single-page app and serves it with an
// SPA fallback (unknown paths return index.html so client-side routing works).
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dist
var dist embed.FS

// Handler returns an http.Handler serving the embedded SPA.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a real file when it exists; otherwise fall back to index.html.
		p := r.URL.Path
		if p == "/" {
			p = "/index.html"
		}
		if f, err := sub.Open(p[1:]); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}
