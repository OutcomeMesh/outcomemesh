//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestProcessRemoteImportedAccountingColdRecovery(t *testing.T) {
	lost := false
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		if args[0] != custodyV2AdmissionCommand || admissionProcessFlag(args, "--action") != "witness-vote" || admissionProcessFlag(args, "--mode") != "run" || lost {
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
			writer.Close()
			t.Fatal(err)
		}
		writer.Close()
		if err = child.Wait(); err == nil || ctx.Err() != nil {
			t.Fatal("lost vote output not observed", err, ctx.Err(), stderr.String())
		}
		if _, err = os.ReadFile(admissionProcessFlag(args, "--out")); err != nil {
			t.Fatal("vote evidence lost", err, stderr.String())
		}
		lost = true
		return ""
	}
	runImportedAccountingCLI(t, driver)
	if !lost {
		t.Fatal("missing lost-output branch")
	}
}
