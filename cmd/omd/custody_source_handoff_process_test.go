//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestProcessSourceHandoffLostOutputAndColdRetry(t *testing.T) {
	lost := false
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		if admissionProcessFlag(args, "--mode") != "run" || admissionProcessFlag(args, "--action") != "transfer" || lost {
			return runProcessCommand(t, 15*time.Second, args...)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		r.Close()
		child := helperCommand(ctx, args...)
		child.Stdout = w
		var errout bytes.Buffer
		child.Stderr = &errout
		if e := child.Start(); e != nil {
			w.Close()
			t.Fatal(e)
		}
		w.Close()
		if e := child.Wait(); e == nil || ctx.Err() != nil {
			t.Fatal("lost output", e, ctx.Err(), errout.String())
		}
		if _, e := os.Stat(admissionProcessFlag(args, "--out")); e != nil {
			t.Fatal("missing retained output", e)
		}
		lost = true
		return ""
	}
	runSourceHandoffCLI(t, driver)
	if !lost {
		t.Fatal("no lost output")
	}
}
