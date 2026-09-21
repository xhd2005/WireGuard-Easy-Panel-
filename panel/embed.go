package main

import (
	"embed"
	"io/fs"
)

//go:embed web/*
var embeddedWebFS embed.FS

// WebAssets 返回剥离了 "web/" 前缀的文件系统，使 index.html 位于根路径。
func WebAssets() fs.FS {
	sub, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		return embeddedWebFS
	}
	return sub
}
