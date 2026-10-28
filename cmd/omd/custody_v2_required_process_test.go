//go:build integration && (darwin || linux)

package main

import (
	"testing"
	"time"
)

func TestProcessCustodyV2RequiredAdmissionAndExecution(t *testing.T) {
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		return runProcessCommand(t, 15*time.Second, args...)
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
	runRequiredCLICampaign(t, driver, start)
}

func TestProcessCustodyV2EnrolledAdmissionAndExecution(t *testing.T) {
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		return runProcessCommand(t, 15*time.Second, args...)
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
	z := newEnrolledCLIFixture(t, driver)
	runRequiredCLIFixtureCampaign(t, z, driver, start)
}
