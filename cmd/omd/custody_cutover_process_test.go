//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestProcessRemoteCutoverColdPreparationAndLostOutput(t *testing.T) {
	lost := false
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		if admissionProcessFlag(args, "--action") != "read-preparation" || admissionProcessFlag(args, "--mode") != "run" || lost {
			return runProcessCommand(t, 15*time.Second, args...)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		child := helperCommand(ctx, args...)
		child.Stdout = writer
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if err = child.Start(); err != nil {
			_ = writer.Close()
			t.Fatal(err)
		}
		_ = writer.Close()
		if err = child.Wait(); err == nil || ctx.Err() != nil {
			t.Fatal("lost output was not observed after immutable export", err, ctx.Err(), stderr.String())
		}
		if _, err = os.ReadFile(admissionProcessFlag(args, "--out")); err != nil {
			t.Fatal("lost output discarded exact proposal", err, stderr.String())
		}
		lost = true
		return ""
	}
	runCutoverCLICampaign(t, driver)
	if !lost {
		t.Fatal("lost output branch not exercised")
	}
}
