package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const custodyV2DeliveryCommand = "work-archive-custody-v2-delivery"

func runCustodyV2DeliveryCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyV2Delivery(ctx, args, os.Stdin, os.Stdout)
}

// Delivery retains public proof only. Creating or opening a required execution
// owner remains a separate reviewed action with its original source gates.
func runCustodyV2Delivery(ctx context.Context, args []string, input io.ReadCloser, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return v2.ErrAdmission
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review or run")
	action := flags.String("action", "", "inbox-create, inbox-enrollment, inbox-serve, inbox-receipt, inbox-binding, delivery, outbox-create, outbox-send, outbox-receipt")
	contextPath := flags.String("context", "", "signed required-profile Context")
	contextID := flags.String("context-id", "", "independent Context ID")
	scopeID := flags.String("scope-id", "", "independent job scope ID")
	bindingID := flags.String("binding-id", "", "independent exact admission binding ID")
	bindingPath := flags.String("binding", "", "complete admission binding; delivery only")
	enrollmentPath := flags.String("enrollment", "", "original public receiver enrollment")
	enrollmentID := flags.String("enrollment-id", "", "independent semantic enrollment ID")
	deliveryPath := flags.String("delivery", "", "exact public delivery intent")
	deliveryID := flags.String("delivery-id", "", "independent semantic delivery ID")
	root := flags.String("root", "", "original inbox or outbox root")
	role := flags.String("role", "", "authority or target; inbox-create only")
	journal := flags.String("journal", "", "original existing source journal; inbox only")
	objects := flags.String("objects", "", "original B object directory; target inbox only")
	peerID := flags.String("recipient-peer-id", "", "independent authenticated receiver peer; inbox-create only")
	signKey := flags.String("sign-key", "", "original role seed; inbox actions, never read in review")
	transportKey := flags.String("transport-key", "", "original authenticated sender or receiver seed")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "local QUIC listen address")
	address := flags.String("address", "", "exact reviewed recipient route; outbox actions")
	timeout := flags.Duration("timeout", 10*time.Second, "100ms..2m network bound")
	output := flags.String("out", "", "immutable public output outside stores and sources")
	expected := flags.String("expected-review-id", "", "exact action review ID")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") || *timeout < remotewire.MinimumTimeout || *timeout > remotewire.MaximumTimeout {
		return v2.ErrAdmission
	}
	selectors := map[string][]string{
		"inbox-create":     {"root", "role", "journal", "objects", "recipient-peer-id", "out"},
		"inbox-enrollment": {"root", "role", "journal", "objects", "recipient-peer-id", "out"},
		"inbox-serve":      {"root", "journal", "objects", "enrollment", "enrollment-id", "sign-key", "transport-key", "listen", "timeout"},
		"inbox-receipt":    {"root", "journal", "objects", "enrollment", "enrollment-id", "sign-key", "out"},
		"inbox-binding":    {"root", "journal", "objects", "enrollment", "enrollment-id", "sign-key", "out"},
		"delivery":         {"binding", "enrollment", "enrollment-id", "out"},
		"outbox-create":    {"root", "delivery", "delivery-id", "address"},
		"outbox-send":      {"root", "delivery", "delivery-id", "address", "transport-key", "listen", "timeout", "out"},
		"outbox-receipt":   {"root", "delivery", "delivery-id", "address", "out"},
	}
	selected, ok := selectors[*action]
	if !ok {
		return v2.ErrAdmission
	}
	allowed := map[string]bool{"mode": true, "action": true, "context": true, "context-id": true, "scope-id": true, "binding-id": true, "expected-review-id": true}
	for _, name := range selected {
		allowed[name] = true
	}
	for name := range custodyCommandPresence(flags) {
		if !allowed[name] {
			return fmt.Errorf("--%s is not used by action %s", name, *action)
		}
	}
	inputs := []string{}
	pins := map[string]string{}
	load := func(path string, limit int) ([]byte, error) {
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		b, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		inputs = append(inputs, p)
		pins[p] = custodyV2ArtifactID(b).String()
		return b, nil
	}
	raw, e := load(*contextPath, v2.MaximumContextBytes)
	if e != nil {
		return e
	}
	c, e := v2.DecodeContext(raw)
	if e != nil || c.Assignment.Policy.Version != v2.PolicyVersionAdmission {
		return errors.Join(v2.ErrAdmission, e)
	}
	cid, _ := c.ID()
	want, e := witnessID("context-id", *contextID)
	if e != nil || cid != want {
		return v2.ErrAdmission
	}
	scope, e := c.Scope()
	if e != nil {
		return e
	}
	sid, _ := scope.ID()
	want, e = witnessID("scope-id", *scopeID)
	if e != nil || sid != want {
		return v2.ErrAdmission
	}
	bid, e := witnessID("binding-id", *bindingID)
	if e != nil {
		return e
	}
	var enrollment v2.AdmissionDeliveryEnrollment
	var d v2.AdmissionDelivery
	var prepared []byte
	var eid, did types.Hash
	var inboxRole v2.AdmissionDeliveryRole
	selectEnrollment := *action == "inbox-create" || *action == "inbox-enrollment"
	if selectEnrollment {
		switch *role {
		case "authority":
			inboxRole = v2.AdmissionDeliveryAuthority
		case "target":
			inboxRole = v2.AdmissionDeliveryTarget
		default:
			return v2.ErrAdmission
		}
	} else if strings.HasPrefix(*action, "inbox-") || *action == "delivery" {
		raw, e := load(*enrollmentPath, v2.MaximumAdmissionDeliveryEnrollmentBytes)
		if e != nil {
			return e
		}
		enrollment, e = v2.DecodeAdmissionDeliveryEnrollment(raw)
		if e != nil {
			return e
		}
		eid, _ = enrollment.ID()
		want, e := witnessID("enrollment-id", *enrollmentID)
		if e != nil || eid != want || enrollment.BindingID != bid {
			return v2.ErrAdmission
		}
		if e := enrollment.Verify(c); e != nil {
			return e
		}
		inboxRole = enrollment.Role
	} else {
		raw, e := load(*deliveryPath, v2.MaximumAdmissionDeliveryBytes)
		if e != nil {
			return e
		}
		d, e = v2.DecodeAdmissionDelivery(raw)
		if e != nil {
			return e
		}
		if e := d.Validate(); e != nil {
			return e
		}
		did, _ = d.ID()
		want, e := witnessID("delivery-id", *deliveryID)
		actual, _ := d.Context.ID()
		if e != nil || did != want || actual != cid || d.Enrollment.BindingID != bid {
			return v2.ErrAdmission
		}
		enrollment = d.Enrollment
		eid, _ = enrollment.ID()
	}
	if *action == "delivery" {
		raw, e := load(*bindingPath, v2.MaximumAdmissionBindingBytes)
		if e != nil {
			return e
		}
		b, e := v2.DecodeAdmissionBinding(raw)
		if e != nil {
			return e
		}
		actual, _ := b.ID()
		if actual != bid {
			return v2.ErrAdmission
		}
		d = v2.AdmissionDelivery{Version: v2.Version2, Enrollment: enrollment, Context: c, Binding: b}
		if e := d.Validate(); e != nil {
			return e
		}
		prepared, e = d.CanonicalBytes()
		if e != nil {
			return e
		}
		did, _ = d.ID()
	}
	isInbox := strings.HasPrefix(*action, "inbox-")
	if *action != "delivery" {
		if *root == "" {
			return v2.ErrAdmission
		}
		*root, e = custodyV2RootPath(*root)
		if e != nil {
			return e
		}
	}
	if isInbox {
		if *journal == "" || (inboxRole == v2.AdmissionDeliveryTarget && *objects == "") || (inboxRole == v2.AdmissionDeliveryAuthority && *objects != "") {
			return v2.ErrAdmission
		}
		if inboxRole == v2.AdmissionDeliveryAuthority && custodyCommandPresence(flags)["objects"] {
			return errors.New("--objects is not used by an authority inbox")
		}
		for _, path := range []*string{journal, objects} {
			if *path == "" {
				continue
			}
			*path, e = filepath.EvalSymlinks(*path)
			if e == nil {
				*path, e = filepath.Abs(*path)
			}
			if e != nil {
				return e
			}
			info, e := os.Lstat(*path)
			if e != nil || !info.IsDir() {
				return errors.Join(v2.ErrAdmission, e)
			}
		}
	}
	var recipient types.Hash
	if selectEnrollment {
		recipient, e = witnessID("recipient-peer-id", *peerID)
		if e != nil {
			return e
		}
	}
	if strings.HasPrefix(*action, "outbox-") {
		if e := v2.ValidateAdmissionDeliveryRoute(*address, enrollment.RecipientPeerID); e != nil {
			return e
		}
	}
	for _, path := range []*string{signKey, transportKey} {
		if *path != "" {
			*path, e = custodyCommandFile(*path)
			if e != nil {
				return e
			}
			inputs = append(inputs, *path)
		}
	}
	if isInbox && !selectEnrollment && *signKey == "" || (*action == "inbox-serve" || *action == "outbox-send") && *transportKey == "" {
		return errors.New("existing role seed paths required; review does not read them")
	}
	requiresOutput := *action != "inbox-serve" && *action != "outbox-create"
	if requiresOutput {
		*output, e = custodyCommandOutput(*output)
		if e != nil {
			return e
		}
		if e := rejectPruneLineageOutputAlias(*output, inputs); e != nil {
			return e
		}
	}
	for _, owner := range []string{*root, *journal, *objects} {
		if owner == "" {
			continue
		}
		for _, p := range append(append([]string{}, inputs...), *output) {
			if p != "" {
				if e := witnessOutside(owner, p); e != nil {
					return e
				}
			}
		}
	}
	var placement types.Hash
	if *action != "delivery" {
		selectedRole := inboxRole
		if !isInbox {
			selectedRole = 0
		}
		placement, e = v2.AdmissionDeliveryReviewPlacement(*root, selectedRole, v2.Sources{Journal: *journal, Objects: *objects})
		if e != nil {
			return e
		}
	}
	public := map[string]any{"action": *action, "context_id": cid.String(), "scope_id": sid.String(), "binding_id": bid.String(), "enrollment_id": eid.String(), "delivery_id": did.String(), "inputs": pins, "root": *root, "role": *role, "recipient_peer_id": *peerID, "journal": *journal, "objects": *objects, "placement_id": placement.String(), "sign_key": *signKey, "transport_key": *transportKey, "address": *address, "listen": *listen, "timeout": timeout.String(), "out": *output, "proof_only": true}
	reviewBytes, e := json.Marshal(public)
	if e != nil {
		return e
	}
	review := types.DomainHash("OMESH/custody/v2/required/admission-delivery/cli/review", reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_delivery_review action=%s review_id=%s context_id=%s binding_id=%s keys_loaded=false stores_opened=false execution_granted=false proof_only=true\n%s\n", *action, review, cid, bid, reviewBytes))
	}
	want, e = witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("admission delivery requires its exact public action review ID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if requiresOutput {
		if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(errors.New("output must be absent; recover to a fresh output"), e)
		}
	}
	publish := func(raw []byte) error {
		if e := publishCustodyCommandArtifact(*output, raw); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_delivery_artifact action=%s artifact_id=%s context_id=%s binding_id=%s enrollment_id=%s delivery_id=%s enrollment_candidate=%t execution_granted=false proof_only=true\n", *action, custodyV2ArtifactID(raw), cid, bid, eid, did, *action == "inbox-enrollment"))
	}
	if prepared != nil {
		return publish(prepared)
	}
	sources := v2.Sources{Journal: *journal, Objects: *objects}
	if selectEnrollment {
		if *action == "inbox-create" {
			enrollment, e = v2.CreateAdmissionInbox(*root, c, sid, bid, inboxRole, sources, recipient)
		} else {
			// This diagnostic exports a candidate, never an automatically adopted
			// enrollment pin or proof that all external pins survived rollback.
			enrollment, e = v2.ReadAdmissionInboxEnrollment(*root, c, sid, bid, inboxRole, sources, recipient)
		}
		if e != nil {
			return e
		}
		eid, _ = enrollment.ID()
		raw, e := enrollment.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(raw)
	}
	if *action == "outbox-create" {
		if e := v2.CreateAdmissionOutbox(*root, d, *address); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_delivery_created enrollment_id=%s delivery_id=%s sent=false execution_granted=false\n", eid, did))
	}
	if strings.HasPrefix(*action, "outbox-") {
		box, e := v2.OpenAdmissionOutbox(*root, d, *address)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, box.Close()) }()
		var receipt v2.AdmissionDeliveryReceipt
		receipt, e = box.ReadReceipt()
		if *action == "outbox-send" && errors.Is(e, os.ErrNotExist) {
			key, er := witnessKey(*transportKey, c.Plan.ClientTransportPublicKey)
			if er != nil {
				return er
			}
			defer clear(key)
			config := libp2ptransport.DefaultConfig()
			config.Listen = []string{*listen}
			host, er := libp2ptransport.New(ctx, key, config, nil)
			if er != nil {
				return er
			}
			defer func() { returnErr = errors.Join(returnErr, host.Close()) }()
			receipt, e = v2.DeliverAdmission(ctx, host, box, *timeout)
		}
		if e != nil {
			return e
		}
		raw, e := receipt.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(raw)
	}
	key, e := witnessKey(*signKey, enrollment.ReceiptPublicKey)
	if e != nil {
		return e
	}
	defer clear(key)
	inbox, e := v2.OpenAdmissionInbox(*root, c, sid, sources, enrollment, key)
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, inbox.Close()) }()
	switch *action {
	case "inbox-receipt":
		r, e := inbox.ReadReceipt()
		if e != nil {
			return e
		}
		raw, e := r.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(raw)
	case "inbox-binding":
		// Require the actual retained receipt as well as a delivery record: a
		// partial receive is not silently exported as completed delivery.
		if _, e := inbox.ReadReceipt(); e != nil {
			return e
		}
		d, e := inbox.Delivery()
		if e != nil {
			return e
		}
		did, _ = d.ID()
		raw, e := d.Binding.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(raw)
	case "inbox-serve":
		return serveAdmissionInboxCLI(ctx, input, out, inbox, *transportKey, *listen, *timeout)
	default:
		return v2.ErrAdmission
	}
}

func serveAdmissionInboxCLI(ctx context.Context, input io.ReadCloser, out io.Writer, inbox *v2.AdmissionInbox, keyPath, listen string, timeout time.Duration) (returnErr error) {
	control, e := ownPruneControlInput(input)
	if e != nil {
		return e
	}
	defer control.Close()
	writer, e := ownPruneEffectOutput(out)
	if e != nil {
		return e
	}
	defer writer.Close()
	// The transport key is independently checked against the pinned recipient
	// peer by StartAdmissionDelivery; it is not a role signing key.
	key, e := readDeliveryTransportKey(keyPath)
	if e != nil {
		return e
	}
	defer clear(key)
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{listen}
	service, e := v2.StartAdmissionDelivery(ctx, inbox, key, config, timeout)
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	enrollment := inbox.Enrollment()
	eid, _ := enrollment.ID()
	if e := writePruneOutputLine(writer, fmt.Sprintf("custody_v2_delivery_serving enrollment_id=%s peer_id=%s address=%s execution_granted=false proof_only=true\n", eid, service.ID(), strings.Join(service.Addresses(), ","))); e != nil {
		return e
	}
	finished := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scan := bufio.NewScanner(control)
		scan.Buffer(make([]byte, 128), 256)
		if scan.Scan() && scan.Text() != "close" {
			finished <- errors.New("admission delivery service accepts only close or EOF")
			return
		}
		finished <- scan.Err()
	}()
	defer func() { _ = control.Close(); <-done }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-finished:
		return e
	}
}

func readDeliveryTransportKey(path string) (ed25519.PrivateKey, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(errors.New("delivery transport seed requires a private regular file"), e)
	}
	return loadPruneOfflineKey(path)
}
