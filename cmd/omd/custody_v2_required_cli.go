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
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const custodyV2RequiredCommand = "work-archive-custody-v2-required"
const custodyV2EnrolledCommand = "work-archive-custody-v2-enrolled"

func runCustodyV2RequiredCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyV2Required(ctx, args, os.Stdin, os.Stdout)
}

// Required owners use the same signed V2 job and wire protocol, with immutable
// admission mode in the assignment. The standalone raw-owner CLI cannot open
// them. Public packet helpers in the existing CLI remain usable for transport.
func runCustodyV2Required(ctx context.Context, args []string, input io.ReadCloser, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return v2.ErrAdmission
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	expectedProfile := v2.PolicyVersionAdmission
	prefix := "custody_v2_required"
	if args[0] == custodyV2EnrolledCommand {
		expectedProfile = v2.PolicyVersionEnrolled
		prefix = "custody_v2_enrolled"
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review or run; exact action review required")
	action := flags.String("action", "", "binding, create-target, serve-target, create-acceptor, accept, resume, receipt, serve-apply-a/b, serve-resume-a/b, serve-status-a/b")
	contextPath := flags.String("context", "", "canonical signed required-profile Context")
	contextID := flags.String("context-id", "", "independent Context ID")
	scopeID := flags.String("scope-id", "", "independent job scope ID")
	bindingPath := flags.String("binding", "", "canonical complete admission binding")
	bindingID := flags.String("binding-id", "", "independent semantic admission binding ID")
	enrollmentPath := flags.String("enrollment", "", "canonical full registry enrollment proof; profile4 only")
	enrollmentID := flags.String("enrollment-id", "", "independent enrollment binding semantic ID")
	registryPath := flags.String("registry", "", "canonical version2 registry genesis; enrollment action")
	registryCertificate := flags.String("registry-certificate", "", "canonical complete registry certificate; enrollment action")
	registryCertificateID := flags.String("registry-certificate-id", "", "independent registry-domain artifact ID")
	genesisPath := flags.String("genesis", "", "canonical assignment admission genesis; binding only")
	genesisID := flags.String("genesis-id", "", "independent assignment admission genesis ID; binding only")
	descriptorID := flags.String("genesis-descriptor-id", "", "independent full genesis descriptor ID; binding only")
	certificates := flags.String("certificates", "", "comma-separated complete contiguous QC prefix paths; binding only")
	certificateIDs := flags.String("certificate-ids", "", "matching V2 artifact IDs; binding only")
	root := flags.String("root", "", "original required owner root")
	journal := flags.String("journal", "", "existing original source journal")
	objects := flags.String("objects", "", "existing original B objects")
	signKey := flags.String("sign-key", "", "authority or target control seed; unused by review")
	replicaKey := flags.String("replica-key", "", "original B replica seed; unused by review")
	transportKey := flags.String("transport-key", "", "original B transport seed; serve-target only")
	in := flags.String("in", "", "bundle or Serve certificate")
	inID := flags.String("in-id", "", "independent input artifact ID")
	proof := flags.String("proof", "", "A Serve-applied receipt; B Serve apply/resume only")
	proofID := flags.String("proof-id", "", "independent A receipt artifact ID")
	bundleID := flags.String("bundle-id", "", "exact retained accepted bundle ID; resume only")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "QUIC listen address; serve-target only")
	timeout := flags.Duration("timeout", 10*time.Second, "100ms..2m RPC bound; serve-target only")
	output := flags.String("out", "", "immutable output outside original roots/sources")
	expected := flags.String("expected-review-id", "", "exact public action review ID")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") || *timeout < remotewire.MinimumTimeout || *timeout > remotewire.MaximumTimeout {
		return v2.ErrAdmission
	}
	permitted := map[string][]string{
		"binding":       {"genesis", "genesis-id", "genesis-descriptor-id", "certificates", "certificate-ids"},
		"create-target": {"root", "journal", "objects"}, "serve-target": {"root", "journal", "objects", "sign-key", "replica-key", "transport-key", "listen", "timeout"}, "create-acceptor": {"root", "journal"},
		"accept": {"root", "journal", "sign-key", "in", "in-id"}, "resume": {"root", "journal", "sign-key", "bundle-id"}, "receipt": {"root", "journal", "sign-key"},
		"serve-apply-a": {"root", "journal", "sign-key", "in", "in-id"}, "serve-resume-a": {"root", "journal", "sign-key", "in", "in-id"}, "serve-status-a": {"root", "journal", "sign-key"},
		"serve-apply-b": {"root", "journal", "objects", "sign-key", "replica-key", "in", "in-id", "proof", "proof-id"}, "serve-resume-b": {"root", "journal", "objects", "sign-key", "replica-key", "in", "in-id", "proof", "proof-id"}, "serve-status-b": {"root", "journal", "objects", "sign-key", "replica-key"},
	}
	if expectedProfile == v2.PolicyVersionEnrolled {
		permitted["enrollment"] = []string{"registry", "registry-certificate", "registry-certificate-id"}
	}
	selectors, ok := permitted[*action]
	if !ok {
		return v2.ErrAdmission
	}
	present := custodyCommandPresence(flags)
	allowed := map[string]bool{"mode": true, "action": true, "context": true, "context-id": true, "scope-id": true, "out": true, "expected-review-id": true}
	if *action != "binding" {
		allowed["binding"] = true
		allowed["binding-id"] = true
	}
	if expectedProfile == v2.PolicyVersionEnrolled && *action != "binding" && *action != "enrollment" {
		allowed["enrollment"] = true
		allowed["enrollment-id"] = true
	}
	for _, s := range selectors {
		allowed[s] = true
	}
	for s := range present {
		if !allowed[s] {
			return fmt.Errorf("--%s is not used by action %s", s, *action)
		}
	}
	inputs := []string{}
	pins := map[string]string{}
	load := func(path, pin string, limit int) ([]byte, error) {
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		b, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		id := custodyV2ArtifactID(b)
		if pin != "" {
			want, e := witnessID("artifact-id", pin)
			if e != nil || want != id {
				return nil, v2.ErrAdmission
			}
		}
		inputs = append(inputs, p)
		pins[p] = id.String()
		return b, nil
	}
	raw, e := load(*contextPath, "", v2.MaximumContextBytes)
	if e != nil {
		return e
	}
	c, e := v2.DecodeContext(raw)
	if e != nil {
		return e
	}
	if c.Assignment.Policy.Version != expectedProfile {
		return v2.ErrAdmission
	}
	cid, _ := c.ID()
	wanted, e := witnessID("context-id", *contextID)
	if e != nil || cid != wanted {
		return v2.ErrAdmission
	}
	scope, e := c.Scope()
	if e != nil {
		return e
	}
	sid, _ := scope.ID()
	wanted, e = witnessID("scope-id", *scopeID)
	if e != nil || sid != wanted {
		return v2.ErrAdmission
	}
	var binding v2.AdmissionBinding
	var bid types.Hash
	var prepared []byte
	if *action == "binding" {
		raw, e := load(*genesisPath, "", v2.MaximumAdmissionGenesisBytes)
		if e != nil {
			return e
		}
		g, e := v2.DecodeAdmissionGenesis(raw)
		if e != nil {
			return e
		}
		gid, _ := g.ID()
		wanted, e := witnessID("genesis-id", *genesisID)
		if e != nil || gid != wanted {
			return v2.ErrAdmission
		}
		did, _ := g.DescriptorID()
		wanted, e = witnessID("genesis-descriptor-id", *descriptorID)
		if e != nil || did != wanted {
			return v2.ErrAdmission
		}
		paths, ids := strings.Split(*certificates, ","), strings.Split(*certificateIDs, ",")
		if *certificates == "" || len(paths) != len(ids) || uint64(len(paths)) > v2.MaxAdmissionEntries(g) {
			return v2.ErrAdmission
		}
		binding = v2.AdmissionBinding{Version: v2.Version2, Genesis: g}
		total := len(raw)
		for i, path := range paths {
			if ids[i] == "" {
				return v2.ErrAdmission
			}
			b, e := load(path, ids[i], v2.MaximumAdmissionCertificateBytes)
			if e != nil {
				return e
			}
			if len(b) > v2.MaximumAdmissionBindingBytes-total {
				return v2.ErrAdmission
			}
			total += len(b)
			q, e := v2.DecodeAdmissionCertificate(b)
			if e != nil {
				return e
			}
			binding.Chain = append(binding.Chain, q)
		}
		if e := binding.Verify(c); e != nil {
			return e
		}
		prepared, e = binding.CanonicalBytes()
		if e != nil {
			return e
		}
		bid, e = binding.ID()
		if e != nil {
			return e
		}
	} else {
		raw, e := load(*bindingPath, "", v2.MaximumAdmissionBindingBytes)
		if e != nil {
			return e
		}
		binding, e = v2.DecodeAdmissionBinding(raw)
		if e != nil {
			return e
		}
		bid, e = binding.ID()
		if e != nil {
			return e
		}
		wanted, e := witnessID("binding-id", *bindingID)
		if e != nil || bid != wanted {
			return v2.ErrAdmission
		}
		if e := binding.Verify(c); e != nil {
			return e
		}
	}
	var enrollment v2.EnrollmentBinding
	var eid types.Hash
	if expectedProfile == v2.PolicyVersionEnrolled && *action != "binding" {
		if *action == "enrollment" {
			raw, e := load(*registryPath, "", wire.MaximumGenesisBytes)
			if e != nil {
				return e
			}
			g, e := wire.DecodeGenesis(raw)
			if e != nil {
				return e
			}
			raw, e = load(*registryCertificate, "", wire.MaximumCertificateBytes)
			if e != nil {
				return e
			}
			want, e := witnessID("registry-certificate-id", *registryCertificateID)
			if e != nil || want != custodyRegistryArtifactID(raw) {
				return v2.ErrEnrollmentRequired
			}
			enrollment = v2.EnrollmentBinding{Version: v2.PolicyVersionEnrolled, Registry: g, Certificate: raw}
		} else {
			raw, e := load(*enrollmentPath, "", v2.MaximumEnrollmentBindingBytes)
			if e != nil {
				return e
			}
			enrollment, e = v2.DecodeEnrollmentBinding(raw)
			if e != nil {
				return e
			}
			eid, e = enrollment.ID()
			if e != nil {
				return e
			}
			wanted, e := witnessID("enrollment-id", *enrollmentID)
			if e != nil || wanted != eid {
				return v2.ErrEnrollmentRequired
			}
		}
		if e := enrollment.Verify(c, binding); e != nil {
			return e
		}
		eid, _ = enrollment.ID()
		if *action == "enrollment" {
			prepared, e = enrollment.CanonicalBytes()
			if e != nil {
				return e
			}
		}
	}
	if *root != "" {
		*root, e = custodyV2RootPath(*root)
		if e != nil {
			return e
		}
	}
	for _, p := range []*string{journal, objects} {
		if *p != "" {
			*p, e = filepath.EvalSymlinks(*p)
			if e != nil {
				return e
			}
			*p, e = filepath.Abs(*p)
			if e != nil {
				return e
			}
			info, e := os.Lstat(*p)
			if e != nil || !info.IsDir() {
				return errors.Join(v2.ErrAdmission, e)
			}
		}
	}
	isTarget := *action == "create-target" || *action == "serve-target" || strings.HasSuffix(*action, "-b")
	isAcceptor := *action != "binding" && *action != "enrollment" && !isTarget
	if *action != "binding" && *action != "enrollment" && (*root == "" || *journal == "") {
		return v2.ErrAdmission
	}
	if isTarget && *objects == "" {
		return v2.ErrAdmission
	}
	var publicKey [32]byte
	if *action == "serve-target" || strings.HasSuffix(*action, "-b") {
		publicKey = c.Assignment.Base.RemoteControlPublicKey
	} else if isAcceptor && *action != "create-acceptor" {
		publicKey = c.Assignment.Base.AuthorityPublicKey
	}
	for _, p := range []*string{signKey, replicaKey, transportKey} {
		if *p != "" {
			*p, e = custodyCommandFile(*p)
			if e != nil {
				return e
			}
			inputs = append(inputs, *p)
		}
	}
	if publicKey != ([32]byte{}) && *signKey == "" {
		return errors.New("existing role seed path required; review does not load it")
	}
	if isTarget && *action != "create-target" && *replicaKey == "" {
		return v2.ErrAdmission
	}
	if *action == "serve-target" && *transportKey == "" {
		return v2.ErrAdmission
	}
	var bundle v2.Bundle
	var resumeID types.Hash
	var serve v2.ServeCertificate
	var parent v2.ServeReceipt
	switch *action {
	case "accept":
		if *inID == "" {
			return v2.ErrAdmission
		}
		raw, e := load(*in, *inID, v2.MaximumBundleBytes)
		if e != nil {
			return e
		}
		bundle, e = v2.DecodeBundle(raw)
		if e != nil {
			return e
		}
		if e := bundle.Verify(c); e != nil {
			return e
		}
	case "resume":
		resumeID, e = witnessID("bundle-id", *bundleID)
		if e != nil {
			return e
		}
	case "serve-apply-a", "serve-resume-a", "serve-apply-b", "serve-resume-b":
		if *inID == "" {
			return v2.ErrAdmission
		}
		raw, e := load(*in, *inID, v2.MaximumServeCertificateBytes)
		if e != nil {
			return e
		}
		serve, e = v2.DecodeServeCertificate(raw)
		if e != nil {
			return e
		}
		if e := serve.Verify(c); e != nil {
			return e
		}
		if isTarget {
			if *proofID == "" {
				return v2.ErrAdmission
			}
			raw, e := load(*proof, *proofID, v2.ServeReceiptBytes)
			if e != nil {
				return e
			}
			parent, e = v2.DecodeServeReceipt(raw)
			if e != nil {
				return e
			}
			if e := parent.Verify(c, serve, v2.ServeAuthority, nil); e != nil {
				return e
			}
		}
	}
	requiresOutput := *action != "create-target" && *action != "create-acceptor" && *action != "serve-target"
	if requiresOutput {
		*output, e = custodyCommandOutput(*output)
		if e != nil {
			return e
		}
		if e := rejectPruneLineageOutputAlias(*output, inputs); e != nil {
			return e
		}
	} else if *output != "" {
		return v2.ErrAdmission
	}
	for _, owner := range []string{*root, *journal, *objects} {
		if owner != "" {
			for _, p := range append(append([]string{}, inputs...), *output) {
				if p != "" {
					if e := witnessOutside(owner, p); e != nil {
						return e
					}
				}
			}
		}
	}
	public := map[string]any{"action": *action, "context_id": cid.String(), "scope_id": sid.String(), "binding_id": bid.String(), "inputs": pins, "root": *root, "journal": *journal, "objects": *objects, "sign_key": *signKey, "replica_key": *replicaKey, "transport_key": *transportKey, "bundle_id": *bundleID, "listen": *listen, "timeout": timeout.String(), "out": *output, "admission_required": true, "enrollment_required": expectedProfile == v2.PolicyVersionEnrolled, "enrollment_id": eid.String()}
	reviewBytes, e := json.Marshal(public)
	if e != nil {
		return e
	}
	reviewDomain := "OMESH/custody/v2/required/cli/review"
	if expectedProfile == v2.PolicyVersionEnrolled {
		reviewDomain = "OMESH/custody/v4/enrolled/cli/review"
	}
	review := types.DomainHash(reviewDomain, reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("%s_review action=%s review_id=%s scope_id=%s binding_id=%s keys_loaded=false owners_opened=false execution_started=false admission_required=true enrollment_id=%s\n%s\n", prefix, *action, review, sid, bid, eid, reviewBytes))
	}
	wanted, e = witnessID("expected-review-id", *expected)
	if e != nil || wanted != review {
		return errors.New("required V2 action requires its exact public review ID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if requiresOutput {
		if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(errors.New("output must be absent before dispatch; recover to a fresh output"), e)
		}
	}
	publish := func(b []byte) error {
		if e := publishCustodyCommandArtifact(*output, b); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("%s_artifact action=%s artifact_id=%s scope_id=%s binding_id=%s admission_required=true proof_refreshed=false enrollment_id=%s\n", prefix, *action, custodyV2ArtifactID(b), sid, bid, eid))
	}
	if prepared != nil {
		return publish(prepared)
	}
	var key ed25519.PrivateKey
	if publicKey != ([32]byte{}) {
		key, e = witnessKey(*signKey, publicKey)
		if e != nil {
			return e
		}
		defer clear(key)
	}
	openTarget := func(replica, control ed25519.PrivateKey) (*v2.Target, error) {
		if expectedProfile == v2.PolicyVersionEnrolled {
			return v2.OpenEnrolledTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, binding, enrollment, replica, control)
		}
		return v2.OpenRequiredTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, binding, replica, control)
	}
	openAcceptor := func() (*v2.Acceptor, error) {
		if expectedProfile == v2.PolicyVersionEnrolled {
			return v2.OpenEnrolledAcceptor(*root, c, sid, *journal, binding, enrollment, key)
		}
		return v2.OpenRequiredAcceptor(*root, c, sid, *journal, binding, key)
	}
	switch *action {
	case "create-target":
		if expectedProfile == v2.PolicyVersionEnrolled {
			e = v2.CreateEnrolledTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, binding, enrollment)
		} else {
			e = v2.CreateRequiredTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, binding)
		}
	case "create-acceptor":
		if expectedProfile == v2.PolicyVersionEnrolled {
			e = v2.CreateEnrolledAcceptor(*root, c, sid, *journal, binding, enrollment)
		} else {
			e = v2.CreateRequiredAcceptor(*root, c, sid, *journal, binding)
		}
	case "serve-target":
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
		replica, e := witnessKey(*replicaKey, c.Assignment.Base.ReplicaPublicKey)
		if e != nil {
			return e
		}
		defer clear(replica)
		transport, e := witnessKey(*transportKey, c.Assignment.Base.RemoteTransportPublicKey)
		if e != nil {
			return e
		}
		defer clear(transport)
		target, e := openTarget(replica, key)
		if e != nil {
			return e
		}
		defer target.Close()
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{*listen}
		service, e := v2.Start(ctx, target, transport, config, *timeout)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
		if e := writePruneOutputLine(writer, fmt.Sprintf("%s_serving scope_id=%s binding_id=%s peer_id=%s address=%s owners_retained=true execution_started=false admission_required=true enrollment_id=%s\n", prefix, sid, bid, service.ID(), strings.Join(service.Addresses(), ","), eid)); e != nil {
			return e
		}
		finished := make(chan error, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			scan := bufio.NewScanner(control)
			scan.Buffer(make([]byte, 128), 256)
			if scan.Scan() && scan.Text() != "close" {
				finished <- errors.New("required V2 service accepts only close or EOF")
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
	default:
		if isAcceptor {
			a, e := openAcceptor()
			if e != nil {
				return e
			}
			defer func() { returnErr = errors.Join(returnErr, a.Close()) }()
			if *action == "serve-status-a" {
				s, e := a.ServeStatus()
				if e != nil {
					return e
				}
				b, e := json.Marshal(s)
				if e != nil {
					return e
				}
				return publish(append(b, '\n'))
			}
			if *action == "serve-apply-a" || *action == "serve-resume-a" {
				r, e := a.ApplyServe(ctx, serve, uint64(time.Now().Unix()), *action == "serve-resume-a")
				if e != nil {
					return e
				}
				b, e := r.CanonicalBytes()
				if e != nil {
					return e
				}
				return publish(b)
			}
			var receipt v2.Receipt
			switch *action {
			case "accept":
				receipt, e = a.Accept(ctx, bundle, uint64(time.Now().Unix()))
			case "resume":
				receipt, e = a.Resume(ctx, resumeID, uint64(time.Now().Unix()))
			case "receipt":
				receipt, e = a.ReadReceipt()
			default:
				return v2.ErrAdmission
			}
			if e != nil {
				return e
			}
			b, e := receipt.CanonicalBytes()
			if e != nil {
				return e
			}
			return publish(b)
		}
		if isTarget {
			replica, e := witnessKey(*replicaKey, c.Assignment.Base.ReplicaPublicKey)
			if e != nil {
				return e
			}
			defer clear(replica)
			t, e := openTarget(replica, key)
			if e != nil {
				return e
			}
			defer func() { returnErr = errors.Join(returnErr, t.Close()) }()
			if *action == "serve-status-b" {
				s, e := t.ServeStatus()
				if e != nil {
					return e
				}
				b, e := json.Marshal(s)
				if e != nil {
					return e
				}
				return publish(append(b, '\n'))
			}
			if *action == "serve-apply-b" || *action == "serve-resume-b" {
				r, e := t.ApplyServe(ctx, serve, parent, uint64(time.Now().Unix()), *action == "serve-resume-b")
				if e != nil {
					return e
				}
				b, e := r.CanonicalBytes()
				if e != nil {
					return e
				}
				return publish(b)
			}
		}
		return v2.ErrAdmission
	}
	if e != nil {
		return e
	}
	return writePruneOutputLine(out, fmt.Sprintf("%s_created action=%s scope_id=%s binding_id=%s execution_started=false admission_required=true enrollment_id=%s\n", prefix, *action, sid, bid, eid))
}
