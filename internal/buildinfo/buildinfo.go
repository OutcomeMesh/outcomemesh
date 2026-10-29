// Package buildinfo identifies a source build without depending on node state.
package buildinfo

import "runtime"

// Release builds set these values with -ldflags. Source builds remain explicit.
var Version = "dev"
var Commit = "unknown"
var Date = "unknown"

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func Current() Info {
	return Info{Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH}
}
