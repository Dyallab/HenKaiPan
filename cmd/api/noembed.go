//go:build !embed_frontend

package main

import "net/http"

func frontendHandler() http.Handler {
	return nil
}
