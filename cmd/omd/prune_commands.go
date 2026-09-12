package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const (
	pruneServeCommand      = "work-prune-command-serve-quic"
	pruneAdmissionCommand  = "work-prune-admission-deliver-quic"
	pruneCompletionCommand = "work-prune-completion-deliver-quic"
)

func runPruneCommandCLI(arguments []string) error {
	// Without Notify, a broken stdout can terminate Go on SIGPIPE before Close
	// runs. Keep EPIPE on the ordinary error path for this command's lifetime.
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runPruneCommand(ctx, arguments, os.Stdout)
}

// The command boundary owns no signer or WorkChain handle. Existing roots and
// independently supplied IDs are mandatory; a failed open never bootstraps them.
func runPruneCommand(ctx context.Context, arguments []string, output io.Writer) (err error) {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("prune command needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name := arguments[0]
	serving := name == pruneServeCommand
	if !serving && name != pruneAdmissionCommand && name != pruneCompletionCommand {
		return errors.New("unsupported prune command; signing and execution are not exposed")
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	assignmentPath := flags.String("assignment", "", "trusted canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently retained assignment ID (required)")
	keyPath := flags.String("key", "", "existing transport-only 32-byte Ed25519 seed file (required)")
	timeout := flags.Duration("timeout", 10*time.Second, "per-exchange timeout, 100ms..2m; not a filesystem deadline")
	var authorityPath, authorityPins, executorPath, executorPins, requestText, serverText, clientText, listen string
	var outboxPath, intentText, address string
	if serving {
		flags.StringVar(&authorityPath, "authority", "", "existing authority root (required)")
		flags.StringVar(&authorityPins, "authority-pins", "", "existing independent authority intent/pin root (required)")
		flags.StringVar(&executorPath, "executor", "", "existing executor root (required)")
		flags.StringVar(&executorPins, "executor-pins", "", "existing independent executor pin root (required)")
		flags.StringVar(&requestText, "request-id", "", "independently retained server request ID (required)")
		flags.StringVar(&serverText, "server-peer-id", "", "externally pinned server transport identity (required)")
		flags.StringVar(&clientText, "client-peer-id", "", "externally pinned allowed client transport identity (required)")
		flags.StringVar(&listen, "listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct QUIC-v1 listen address")
	} else {
		flags.StringVar(&outboxPath, "outbox", "", "existing typed client outbox (required; never initialized here)")
		flags.StringVar(&intentText, "intent-id", "", "independently retained outbox intent ID (required)")
		flags.StringVar(&address, "peer", "", "explicit server route, not an identity pin (required)")
	}
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	if *assignmentPath == "" || *keyPath == "" || *timeout < admissionwire.MinimumTimeout || *timeout > admissionwire.MaximumTimeout {
		return errors.New("assignment, key and a timeout within 100ms..2m are required")
	}
	assignmentID, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	var requestID, serverID, clientID, intentID types.Hash
	if serving {
		if authorityPath == "" || authorityPins == "" || executorPath == "" || executorPins == "" || listen == "" {
			return errors.New("all four existing authority/executor roots and a listen address are required")
		}
		if requestID, err = pruneExternalID("request-id", requestText); err != nil {
			return err
		}
		if serverID, err = pruneExternalID("server-peer-id", serverText); err != nil {
			return err
		}
		if clientID, err = pruneExternalID("client-peer-id", clientText); err != nil {
			return err
		}
	} else {
		if outboxPath == "" || address == "" {
			return errors.New("existing outbox and explicit peer route are required")
		}
		if intentID, err = pruneExternalID("intent-id", intentText); err != nil {
			return err
		}
	}
	encoded, err := readRegularArtifact(*assignmentPath, custodyauthority.MaximumAssignmentBytes)
	if err != nil {
		return fmt.Errorf("read assignment: %w", err)
	}
	assignment, err := custodyauthority.DecodeAssignment(encoded)
	if err != nil {
		return err
	}
	if id, err := assignment.ID(); err != nil || id != assignmentID {
		return errors.Join(custodyauthority.ErrAssignment, err)
	}
	seed, err := readRegularArtifact(*keyPath, ed25519.SeedSize)
	if err != nil {
		return fmt.Errorf("read transport key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("transport key must contain exactly 32 seed bytes")
	}
	key := ed25519.NewKeyFromSeed(seed)
	config := libp2ptransport.DefaultConfig()
	if serving {
		service, openErr := authoritystore.OpenPruneCommandService(authoritystore.PruneCommandServiceConfig{
			AuthorityPath: authorityPath, AuthorityPinsPath: authorityPins, ExecutorPath: executorPath, ExecutorPinsPath: executorPins,
			Assignment: assignment, AssignmentID: assignmentID, RequestID: requestID,
			ServerPeerID: serverID, ClientPeerID: clientID, Timeout: *timeout,
		})
		if openErr != nil {
			return openErr
		}
		defer func() { err = errors.Join(err, service.Close()) }()
		config.Listen = []string{listen}
		if err := service.Start(ctx, key, config); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "serving_work_prune_commands peer_id=%s client_peer_id=%s assignment_id=%s request_id=%s listen=%s command_only=true execution_enabled=false automatic_resume=false\n",
			serverID, clientID, assignmentID, requestID, strings.Join(service.Addresses(), ",")); err != nil {
			return err // the deferred Close drains owners even if readiness cannot be reported
		}
		<-service.Done()
		return nil // Close returns any retained storage/shutdown failure
	}
	delivery := authoritystore.PruneDeliveryConfig{Path: outboxPath, Assignment: assignment, IntentID: intentID,
		Address: address, Timeout: *timeout, Transport: config}
	var entryID, nonce types.Hash
	var unconfirmed error
	if name == pruneAdmissionCommand {
		ack, err := authoritystore.DeliverPruneAdmission(ctx, key, delivery)
		if err != nil {
			return err
		}
		entryID, nonce, unconfirmed = ack.EntryID, ack.Nonce, admissionwire.ErrUnconfirmed
	} else {
		ack, err := authoritystore.DeliverPruneCompletion(ctx, key, delivery)
		if err != nil {
			return err
		}
		entryID, nonce, unconfirmed = ack.EntryID, ack.Nonce, completionwire.ErrUnconfirmed
	}
	// A failed stdout write may follow a durable receipt. Preserve that ambiguity;
	// never erase the outbox or retry just to obtain a printable result.
	if _, err := fmt.Fprintf(output, "work_prune_delivery command=%s assignment_id=%s intent_id=%s entry_id=%s nonce=%s delivery_confirmed=true historical_only=true execution_authorized=false automatic_retry=false\n",
		name, assignmentID, intentID, entryID, nonce); err != nil {
		return errors.Join(unconfirmed, err)
	}
	return nil
}

func pruneExternalID(name, encoded string) (types.Hash, error) {
	id, err := parseHash(encoded)
	if err != nil || id.IsZero() {
		return types.Hash{}, fmt.Errorf("%s must be a nonzero independently retained 32-byte ID", name)
	}
	return id, nil
}

// All flags in the prune transport/preparation commands take a value. Wrap their setters so a
// repeated trust pin/path cannot silently override an earlier reviewed value.
func parsePruneFlags(flags *flag.FlagSet, arguments []string) error {
	flags.VisitAll(func(f *flag.Flag) { f.Value = &pruneOnceFlag{value: f.Value} })
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("prune commands do not accept positional arguments")
	}
	return nil
}

type pruneOnceFlag struct {
	value flag.Value
	set   bool
}

func (value *pruneOnceFlag) String() string {
	if value == nil || value.value == nil {
		return ""
	}
	return value.value.String()
}

func (value *pruneOnceFlag) Set(encoded string) error {
	if value.set {
		return errors.New("each flag may be supplied only once")
	}
	value.set = true
	return value.value.Set(encoded)
}
