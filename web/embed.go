package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var DistFS embed.FS

// GetFS returns the http.FileSystem rooted at the embedded dist directory.
func GetFS() http.FileSystem {
	sub, err := fs.Sub(DistFS, "dist")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
