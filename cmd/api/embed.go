//go:build embed_frontend

package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed frontend-dist
var frontend embed.FS

func frontendHandler() http.Handler {
	sub, err := fs.Sub(frontend, "frontend-dist")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
