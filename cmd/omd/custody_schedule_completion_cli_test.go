package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

// Called after the existing complete migration and real QUIC exchange fixture.
func completeScheduledCustodyCLI(t testing.TB, f *managedCustodyPairCLIFixture, scheduleArgs []string) {
	t.Helper()
	before := f.snapshot(t)
	consumerKey, authorityKey := filepath.Join(t.TempDir(), "consumer.key"), filepath.Join(t.TempDir(), "authority.key")
	writePruneCLIFile(t, consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, authorityKey, pruneCLIKey(1).Seed())
	for i, purpose := range []string{"audit", "serve"} {
		admission, path, journal := f.config.Audit.Admission, f.audit.admissionPath, f.config.Audit.JournalPath
		if purpose == "serve" {
			admission, path, journal = f.config.Serve.Admission, f.audit.serve.admissionPath, f.config.Serve.JournalPath
		}
		ticket, _ := admission.ID()
		common := append(custodyCommandCLICommonArgs(f.audit), scheduleArgs...)
		capture := append([]string{custodyTerminalCommand}, common...)
		capture = append(capture, "--purpose", purpose, "--admission", path, "--admission-id", ticket.String(), "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", journal)
		terminalPath := filepath.Join(t.TempDir(), "terminal.omct")
		control := startCustodyCommandControl(t, append(capture, "--out", terminalPath), nil)
		custodyCommandControlLine(t, control, "work_archive_custody_command_ready")
		review := custodyCommandControlReview(t, control)
		io.WriteString(control.input, "capture "+review+"\n")
		result := custodyCommandControlLine(t, control, "work_archive_custody_command_result")
		io.WriteString(control.input, "close\n")
		if err := control.wait(t); err != nil {
			t.Fatal(err)
		}
		terminalID, err := managedCustodyExternalID("terminal-id", result["terminal_id"])
		if err != nil {
			t.Fatal(err)
		}
		terminal, err := store.LoadCustodyTerminalFile(terminalPath, terminalID)
		if err != nil || terminal.Version != store.CustodyTerminalVersion1 || terminal.ScheduleID != before.Authority.ScheduleID || terminal.Admission != admission {
			t.Fatal("wrong scheduled terminal", err)
		}
		position := f.snapshot(t).Confirmed
		sign := append([]string{custodyCommandSignCommand}, common...)
		sign = append(sign, "--kind", "complete", "--purpose", purpose, "--expected-sequence", strconv.FormatUint(position.Sequence, 10), "--expected-head", position.HeadID.String(), "--admission", path, "--admission-id", ticket.String(), "--terminal", terminalPath, "--terminal-id", terminalID.String())
		token := custodyCommandReviewToken(t, sign)
		commandPath := filepath.Join(t.TempDir(), "complete.command")
		if err := runCustodyCommand(t.Context(), append(append([]string{}, sign...), "--mode", "sign", "--consumer-key", consumerKey, "--expected-review-id", token, "--out", commandPath), nil, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		cosign := append([]string{}, sign...)
		cosign[0] = custodyCommandCosignCommand
		cosign = append(cosign, "--command", commandPath)
		token = custodyCommandReviewToken(t, cosign)
		entryPath := filepath.Join(t.TempDir(), "complete.entry")
		if err := runCustodyCommand(t.Context(), append(cosign, "--mode", "sign", "--authority-key", authorityKey, "--expected-review-id", token, "--out", entryPath), nil, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		raw, err := readRegularArtifact(entryPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.DecodeEntry(raw)
		if err != nil {
			t.Fatal(err)
		}
		entryID, _ := entry.ID()
		if entry.Command.ScheduleID != terminal.ScheduleID || entry.Command.TicketID != ticket {
			t.Fatal("completion changed ticket")
		}
		apply := append([]string{custodyCommandApplyCommand}, common...)
		apply = append(apply, "--purpose", purpose, "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", journal, "--entry", entryPath, "--entry-id", entryID.String(), "--terminal", terminalPath, "--terminal-id", terminalID.String(), "--admission", path, "--admission-id", ticket.String())
		for retry := 0; retry < 2; retry++ {
			control = startCustodyCommandControl(t, apply, nil)
			custodyCommandControlLine(t, control, "work_archive_custody_command_ready")
			token = custodyCommandControlReview(t, control)
			io.WriteString(control.input, "apply "+token+"\n")
			result = custodyCommandControlLine(t, control, "work_archive_custody_command_result")
			if result["entry_id"] != entryID.String() {
				t.Fatal("wrong completion", result)
			}
			io.WriteString(control.input, "close\n")
			if err := control.wait(t); err != nil {
				t.Fatal(err)
			}
		}
		after := f.snapshot(t)
		if after.Authority.Pending != before.Authority.Pending-uint16(i+1) || len(after.Authority.Operations) != len(before.Authority.Operations) || after.Confirmed.Sequence != before.Confirmed.Sequence+uint64(i+1) {
			t.Fatal("completion reset accounting")
		}
	}
}
