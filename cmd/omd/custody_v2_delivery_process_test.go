//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestProcessCustodyV2DeliveryColdStoresAndLostOutput(t *testing.T) {
	runProcessAdmissionDeliveryCampaign(t, false)
}
func TestProcessCustodyV2EnrolledDeliveryColdStoresAndLostOutput(t *testing.T) {
	runProcessAdmissionDeliveryCampaign(t, true)
}
func runProcessAdmissionDeliveryCampaign(t *testing.T, enrolled bool) {
	t.Helper()
	lost := false
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		if (args[0] != custodyV2DeliveryCommand && args[0] != custodyV2EnrolledDeliveryCommand) || admissionProcessFlag(args, "--action") != "outbox-send" || admissionProcessFlag(args, "--mode") != "run" || lost {
			return runProcessCommand(t, 15*time.Second, args...)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		reader, writer, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		_ = reader.Close()
		child := helperCommand(ctx, args...)
		child.Stdout = writer
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if e := child.Start(); e != nil {
			_ = writer.Close()
			t.Fatal(e)
		}
		_ = writer.Close()
		if e := child.Wait(); e == nil || ctx.Err() != nil {
			t.Fatal("lost stdout was not observed after delivery", e, ctx.Err(), stderr.String())
		}
		if _, e := os.ReadFile(admissionProcessFlag(args, "--out")); e != nil {
			t.Fatal("receipt not retained before lost command output", e, stderr.String())
		}
		lost = true
		return ""
	}
	start := func(t testing.TB, args []string, prefix string) (string, func()) {
		t.Helper()
		p, ready := startV2Native(t, args, prefix)
		return ready["address"], func() {
			p.send(t, "close\n")
			if e := p.wait(t); e != nil {
				t.Fatal(e, p.stderr.String())
			}
			_ = p.input.Close()
			_ = p.output.Close()
		}
	}
	if enrolled {
		z := newEnrolledCLIFixtureWithLifetime(t, driver, 600)
		runAdmissionDeliveryCLIFixtureCampaign(t, z, driver, start, start)
	} else {
		runAdmissionDeliveryCLICampaign(t, driver, start)
	}
	if !lost {
		t.Fatal("native lost output boundary not exercised")
	}
}
