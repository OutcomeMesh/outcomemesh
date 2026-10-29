package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/outcomemesh/outcomemesh/internal/buildinfo"
)

func runVersion(args []string, out io.Writer) error {
	info := buildinfo.Current()
	if len(args) == 1 && args[0] == "--json" {
		return json.NewEncoder(out).Encode(info)
	}
	if len(args) != 0 {
		return errors.New("usage: omd version [--json]")
	}
	_, err := fmt.Fprintf(out, "OutcomeMesh Core %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n", info.Version, info.Commit, info.BuiltAt, info.Go, info.OS, info.Arch)
	return err
}
