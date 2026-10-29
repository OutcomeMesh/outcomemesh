package main

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"
)

func TestVersionReportsCompiledToolchainWithoutOpeningNode(t *testing.T) {
	var out bytes.Buffer
	if err := runVersion([]string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var info map[string]string
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info["go"] != runtime.Version() || info["os"] != runtime.GOOS || info["arch"] != runtime.GOARCH || info["version"] != "dev" {
		t.Fatal(info)
	}
	out.Reset()
	if err := runVersion(nil, &out); err != nil || !strings.Contains(out.String(), "OutcomeMesh Core dev") {
		t.Fatal(err)
	}
	if err := runVersion([]string{"--data-dir", "unexpected"}, &out); err == nil {
		t.Fatal("unknown flags accepted")
	}
	if err := runVersion(nil, brokenVersionWriter{}); err == nil {
		t.Fatal("output failure ignored")
	}
}

type brokenVersionWriter struct{}

func (brokenVersionWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
