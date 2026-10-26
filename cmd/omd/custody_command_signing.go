package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// Signing reads only fixed historical inputs. It never opens an authority,
// selects a latest position, changes a timestamp, or executes a command.
func runCustodyCommandSigning(ctx context.Context, args []string, output io.Writer) error {
	name := args[0]
	cosign := name == custodyCommandCosignCommand
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	common := addCustodyCommandScopeFlags(f)
	mode := f.String("mode", "review", "review (default), or sign")
	kindText := f.String("kind", "", "admit or complete")
	purposeText := f.String("purpose", "", "audit or serve")
	sequenceText := f.String("expected-sequence", "", "explicit fixed authority sequence, including zero")
	headText := f.String("expected-head", "", "explicit fixed authority head")
	consumerText := f.String("consumer-public-key", "", "Admit only: exact authorized consumer public key")
	challengePath := f.String("challenge", "", "Serve Admit only: exact signed challenge")
	challengeText := f.String("challenge-id", "", "Serve Admit only: independently retained challenge ID")
	admissionPath := f.String("admission", "", "Complete only: exact co-signed admission")
	admissionText := f.String("admission-id", "", "Complete only: independently retained admission ID")
	terminalPath := f.String("terminal", "", "Complete only: captured terminal envelope")
	terminalText := f.String("terminal-id", "", "Complete only: independently retained terminal envelope ID")
	reviewText := f.String("expected-review-id", "", "sign mode: exact signature review ID")
	outText := f.String("out", "", "sign mode: immutable canonical output")
	keyName := "consumer-key"
	if cosign {
		keyName = "authority-key"
	}
	keyPath := f.String(keyName, "", "sign mode: existing role-specific 32-byte Ed25519 seed")
	var commandPath string
	if cosign {
		f.StringVar(&commandPath, "command", "", "exact consumer-signed canonical command")
	}
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	if *mode != "review" && *mode != "sign" {
		return errors.New("custody signing mode must be review or sign")
	}
	if *mode == "review" {
		if err := custodyCommandForbid(present, keyName, "out", "expected-review-id"); err != nil {
			return err
		}
	}
	if *mode == "sign" && (*keyPath == "" || *outText == "" || *reviewText == "") {
		return errors.New("sign requires the role-specific seed, expected-review-id and immutable output")
	}
	scope, paths, err := common.load()
	if err != nil {
		return err
	}
	purpose, err := custodyCommandPurpose(*purposeText)
	if err != nil {
		return err
	}
	sequence, err := strconv.ParseUint(*sequenceText, 10, 64)
	if err != nil || strconv.FormatUint(sequence, 10) != *sequenceText {
		return errors.New("expected-sequence requires an explicit canonical nonnegative decimal")
	}
	head, err := managedCustodyExternalID("expected-head", *headText)
	if err != nil {
		return err
	}
	position := custodyauthority.Position{Sequence: sequence, HeadID: head}
	var draft custodyauthority.Command
	var challenge workarchive.CustodyChallenge
	var admissionID, terminalID, challengeID types.Hash
	var admissionFile, terminalFile, challengeFile string
	switch *kindText {
	case "admit":
		if err := custodyCommandForbid(present, "admission", "admission-id", "terminal", "terminal-id"); err != nil {
			return err
		}
		consumer, err := managedCustodyExternalID("consumer-public-key", *consumerText)
		if err != nil {
			return err
		}
		if purpose == custodyauthority.Serve {
			challenge, challengeFile, err = custodyCommandChallenge(*challengePath, *challengeText)
			if err != nil {
				return err
			}
			challengeID, _ = challenge.ID()
		} else if err := custodyCommandForbid(present, "challenge", "challenge-id"); err != nil {
			return err
		}
		draft, err = authoritystore.BuildCustodyAdmitCommand(scope, purpose, [32]byte(consumer), position, challenge)
	case "complete":
		if err := custodyCommandForbid(present, "consumer-public-key", "challenge", "challenge-id"); err != nil {
			return err
		}
		var admission custodyauthority.Entry
		admission, admissionFile, err = custodyCommandEntry(*admissionPath, *admissionText)
		if err != nil {
			return err
		}
		admissionID, _ = admission.ID()
		if admission.Command.Purpose != purpose {
			return errors.New("selected purpose differs from completion admission")
		}
		terminal, canonical, loadErr := custodyCommandTerminal(*terminalPath, *terminalText)
		if loadErr != nil {
			return loadErr
		}
		terminalFile = canonical
		terminalID, _ = terminal.ID()
		draft, err = authoritystore.BuildCustodyCompleteCommand(scope, admission, terminal, position)
	default:
		return errors.New("kind must be admit or complete")
	}
	if err != nil {
		return err
	}
	command := draft
	var commandFile string
	if cosign {
		commandFile, err = custodyCommandFile(commandPath)
		if err != nil {
			return err
		}
		b, err := readRegularArtifact(commandFile, custodyauthority.MaximumCommandBytes)
		if err != nil {
			return err
		}
		command, err = custodyauthority.DecodeCommand(b)
		if err != nil {
			return err
		}
		unsigned := command
		unsigned.Signature = [64]byte{}
		if unsigned != draft {
			return errors.New("consumer-signed command differs from the complete reviewed scope")
		}
	}
	reviewID, err := authoritystore.CustodyCommandReviewID(scope.Assignment, draft, purpose)
	if cosign {
		reviewID, err = authoritystore.CustodyEntryReviewID(scope.Assignment, command, purpose)
	}
	if err != nil {
		return err
	}
	var entryID types.Hash
	published, reused := false, false
	if *mode == "sign" {
		expected, err := managedCustodyExternalID("expected-review-id", *reviewText)
		if err != nil || expected != reviewID {
			return errors.Join(errors.New("signature requires the exact canonical review ID"), err)
		}
		out, err := custodyCommandOutput(*outText)
		if err != nil {
			return err
		}
		inputs := []string{paths.Assignment, paths.Manifest, paths.InitialReceipt, paths.Intent, paths.PreviousReceipt}
		for _, path := range []string{commandFile, admissionFile, terminalFile, challengeFile} {
			if path != "" {
				inputs = append(inputs, path)
			}
		}
		if err := rejectPruneLineageOutputAlias(out, inputs); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Exact retries inspect the canonical output before accessing the seed.
		// This also recovers a committed artifact after stdout was lost.
		maximum := custodyauthority.MaximumCommandBytes
		if cosign {
			maximum = custodyauthority.MaximumEntryBytes
		}
		existing, loadErr := readRegularArtifact(out, maximum)
		var signed []byte
		if loadErr == nil {
			if cosign {
				e, err := custodyauthority.DecodeEntry(existing)
				if err != nil {
					return err
				}
				if e.Command != command || e.AuthorityPublicKey != scope.Assignment.AuthorityPublicKey {
					return errors.New("immutable output conflicts with the reviewed co-signature")
				}
				entryID, _ = e.ID()
			} else {
				c, err := custodyauthority.DecodeCommand(existing)
				if err != nil {
					return err
				}
				c.Signature = [64]byte{}
				if c != draft {
					return errors.New("immutable output conflicts with the reviewed command")
				}
			}
			signed = existing
			reused = true
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		} else {
			// Every public scope and review check above precedes this first read.
			key, err := loadPruneOfflineKey(*keyPath)
			if err != nil {
				return err
			}
			if cosign {
				e, err := authoritystore.CosignReviewedCustodyCommand(scope.Assignment, command, purpose, expected, key)
				if err != nil {
					return err
				}
				signed, err = e.CanonicalBytes()
				if err != nil {
					return err
				}
				entryID, _ = e.ID()
			} else {
				c, err := authoritystore.SignReviewedCustodyCommand(scope.Assignment, draft, purpose, expected, key)
				if err != nil {
					return err
				}
				signed, err = c.CanonicalBytes()
				if err != nil {
					return err
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishCustodyCommandArtifact(out, signed); err != nil {
			return err
		}
		published = true
	}
	public, err := json.MarshalIndent(struct {
		Scope              custodyCommandPublicScope `json:"scope"`
		Command            custodyauthority.Command  `json:"unsigned_command"`
		AuthorityPublicKey string                    `json:"authority_public_key"`
		Purpose            string                    `json:"selected_purpose"`
		ChallengeID        string                    `json:"challenge_id"`
		ChallengeFile      string                    `json:"challenge_file"`
		AdmissionID        string                    `json:"admission_id"`
		AdmissionFile      string                    `json:"admission_file"`
		TerminalID         string                    `json:"terminal_id"`
		TerminalFile       string                    `json:"terminal_file"`
		CommandFile        string                    `json:"consumer_command_file"`
	}{custodyCommandPublic(scope, paths), draft, fmt.Sprintf("%x", scope.Assignment.AuthorityPublicKey), *purposeText, challengeID.String(), challengeFile, admissionID.String(), admissionFile, terminalID.String(), terminalFile, commandFile}, "", "  ")
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_signing command=%s mode=%s kind=%s purpose=%s assignment_id=%s expected_sequence=%d expected_head=%s operation_id=%s ticket_id=%s evidence_id=%s actor_public_key=%x authority_public_key=%x review_id=%s entry_id=%s artifact_published=%t artifact_reused=%t historical_only=true execution_authorized=false\nscope:\n%s\nwork_archive_custody_signing_scope_end\n", name, *mode, *kindText, *purposeText, scope.AssignmentID, draft.ExpectedSequence, draft.ExpectedHead, draft.OperationID, draft.TicketID, draft.EvidenceID, draft.ActorPublicKey, scope.Assignment.AuthorityPublicKey, reviewID, entryID, published, reused, public))
}

// The caller has already canonicalized an existing output parent. Unlike the
// generic archive publisher this never initializes a missing directory.
func publishCustodyCommandArtifact(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	// A retained exact artifact needs no new directory entry or allocation.
	// Confirm its bounded bytes and inode durability before considering a
	// temporary file, so stdout recovery also works under disk pressure.
	if existing, err := readRegularArtifact(path, len(encoded)); err == nil {
		if !bytes.Equal(existing, encoded) {
			return errors.New("existing immutable custody command conflicts with the reviewed bytes")
		}
		if err := syncExactRegularArtifact(path, encoded, nil); err != nil {
			return errors.Join(errors.New("existing immutable custody command is not confirmed"), err)
		}
		return syncCustodyArtifactDirectory(directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-custody-command-*")
	if err != nil {
		return err
	}
	defer func() { _ = temporary.Close(); _ = os.Remove(temporary.Name()) }()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	n, err := temporary.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := syncExactRegularArtifact(path, encoded, nil); err != nil {
			return errors.Join(errors.New("existing immutable custody command is not confirmed"), err)
		}
	}
	return syncCustodyArtifactDirectory(directory)
}
