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

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	pruneLineageExtractCommand      = "work-prune-lineage-extract"
	maximumPruneLineageSourcesBytes = 256 << 10
	pruneLineageExtractReviewDomain = "OMESH/custody-prune/lineage-extract/review/v0"
)

type pruneLineageSourcePaths struct {
	AssignmentID             string `json:"assignment_id"`
	Journal                  string `json:"journal"`
	Checkpoint               string `json:"checkpoint"`
	CheckpointID             string `json:"checkpoint_id"`
	Manifest                 string `json:"manifest"`
	InitialReceipt           string `json:"initial_receipt"`
	MaximumChallengeLifetime uint64 `json:"maximum_challenge_lifetime"`
	MaximumProofAge          uint64 `json:"maximum_proof_age"`
	MaximumRenewalTerm       uint64 `json:"maximum_renewal_term"`
}

type pruneLineageExtractInput struct {
	source authoritystore.ArchivePruneLineageSource
	paths  pruneLineageSourcePaths
}

// This command reads already reviewed source checkpoints. It never captures a
// newer head or turns a historical prefix into live execution permission.
func runPruneLineageExtract(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil || output == nil || len(arguments) == 0 || arguments[0] != pruneLineageExtractCommand {
		return errors.New("lineage extraction needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet(pruneLineageExtractCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review sources (default), extract the exact reviewed evidence, or verify a retained file")
	inventoryPath := flags.String("inventory", "", "existing canonical lineage inventory file (required)")
	inventoryText := flags.String("inventory-id", "", "independently retained inventory ID (required)")
	policyText := flags.String("policy-id", "", "independently retained lineage policy ID (required)")
	sourcesPath := flags.String("sources", "", "existing bounded source-path JSON file (review/extract only)")
	outPath := flags.String("out", "", "evidence file in an existing dedicated parent (required)")
	expectedReviewText := flags.String("expected-review-id", "", "independently retained exact review ID (extract only)")
	evidenceText := flags.String("evidence-id", "", "independently retained evidence ID (verify only)")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	present := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { present[f.Name] = true })
	if *mode != "review" && *mode != "extract" && *mode != "verify" {
		return errors.New("mode must be review, extract or verify")
	}
	if *inventoryPath == "" || *outPath == "" {
		return errors.New("inventory and evidence output paths are required")
	}
	if *mode == "verify" {
		if present["sources"] || present["expected-review-id"] {
			return errors.New("verify forbids sources and expected-review-id flags, including empty values")
		}
	} else if *sourcesPath == "" || present["evidence-id"] || (*mode == "review" && present["expected-review-id"]) {
		return errors.New("review/extract require sources; evidence-id is verify-only and expected-review-id is extract-only")
	}
	inventoryID, err := pruneExternalID("inventory-id", *inventoryText)
	if err != nil {
		return err
	}
	policyID, err := pruneExternalID("policy-id", *policyText)
	if err != nil {
		return err
	}
	var expectedReviewID, expectedEvidenceID types.Hash
	if *mode == "extract" {
		expectedReviewID, err = pruneExternalID("expected-review-id", *expectedReviewText)
	} else if *mode == "verify" {
		expectedEvidenceID, err = pruneExternalID("evidence-id", *evidenceText)
	}
	if err != nil {
		return err
	}
	inventoryFile, _, err := canonicalPruneLineageFile(*inventoryPath)
	if err != nil {
		return err
	}
	inventory, err := authoritystore.LoadArchivePruneInventoryFile(inventoryFile, inventoryID, policyID)
	if err != nil {
		return err
	}
	if inventory.Mode != authoritystore.ArchivePruneLineage {
		return authoritystore.ErrPruneLineageEvidence
	}
	out, err := canonicalPruneLineageOutput(*outPath)
	if err != nil {
		return err
	}
	if *mode == "verify" {
		if err := rejectPruneLineageOutputAlias(out, []string{inventoryFile}); err != nil {
			return err
		}
		if _, err := authoritystore.LoadArchivePruneLineageEvidenceFile(ctx, out, inventory, inventoryID, policyID, expectedEvidenceID); err != nil {
			return err
		}
		return writePruneOutputLine(output, fmt.Sprintf("work_prune_lineage_extraction mode=verify inventory_id=%s policy_id=%s evidence_id=%s artifact_published=false evidence_verified=true owners_closed=true historical_only=true execution_authorized=false\n", inventoryID, policyID, expectedEvidenceID))
	}
	metadataFile, _, err := canonicalPruneLineageFile(*sourcesPath)
	if err != nil {
		return err
	}
	encoded, err := readRegularArtifact(metadataFile, maximumPruneLineageSourcesBytes)
	if err != nil {
		return err
	}
	paths, err := decodePruneLineageSourcePaths(encoded)
	if err != nil {
		return err
	}
	inputs, err := loadPruneLineageSources(ctx, inventory, paths, filepath.Dir(metadataFile), inventoryFile, metadataFile, out)
	if err != nil {
		return err
	}
	sources := make([]authoritystore.ArchivePruneLineageSource, len(inputs))
	for i := range inputs {
		sources[i] = inputs[i].source
	}
	evidence, err := authoritystore.ExtractArchivePruneLineageEvidence(ctx, inventory, inventoryID, policyID, sources)
	if err != nil {
		return err
	}
	evidenceID, err := evidence.ID()
	if err != nil {
		return err
	}
	reviewID := pruneLineageExtractionReview(inventoryID, policyID, evidenceID, inventoryFile, metadataFile, out, inputs)
	if *mode == "extract" {
		if expectedReviewID != reviewID {
			return errors.New("lineage extraction does not match the exact retained review ID")
		}
		if err := authoritystore.SaveArchivePruneLineageEvidenceFile(ctx, out, evidence, evidenceID); err != nil {
			return err
		}
	}
	// Extraction has released every source owner before publication/output. A
	// failed stdout write preserves any published file for explicit verify/retry.
	if err := writePruneOutputLine(output, fmt.Sprintf("work_prune_lineage_extraction mode=%s inventory_id=%s policy_id=%s review_id=%s evidence_id=%s artifact_published=%t evidence_verified=false owners_closed=true historical_only=true execution_authorized=false\n", *mode, inventoryID, policyID, reviewID, evidenceID, *mode == "extract")); err != nil {
		return err
	}
	if *mode == "review" {
		return writePruneLineageScope(output, inventoryFile, metadataFile, out, inputs)
	}
	return nil
}

func writePruneLineageScope(output io.Writer, inventoryFile, metadataFile, out string, inputs []pruneLineageExtractInput) error {
	scope := struct {
		Inventory string                    `json:"inventory"`
		Sources   string                    `json:"sources"`
		Out       string                    `json:"out"`
		Inputs    []pruneLineageSourcePaths `json:"inputs"`
	}{Inventory: inventoryFile, Sources: metadataFile, Out: out, Inputs: make([]pruneLineageSourcePaths, len(inputs))}
	for i, input := range inputs {
		scope.Inputs[i] = input.paths
		scope.Inputs[i].AssignmentID = input.source.AssignmentID.String()
		scope.Inputs[i].CheckpointID = input.source.CheckpointID.String()
	}
	encoded, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, "scope:\n"+string(encoded)+"\n")
}

// This path metadata has only scalar fields. Token decoding preserves duplicate
// keys and exact field spelling rather than accepting JSON's last-key wins or
// encoding/json's case-insensitive struct-field matching.
func decodePruneLineageSourcePaths(encoded []byte) ([]pruneLineageSourcePaths, error) {
	if len(encoded) == 0 || len(encoded) > maximumPruneLineageSourcesBytes {
		return nil, errors.New("lineage source metadata exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, errors.New("lineage sources must be a JSON array")
	}
	var result []pruneLineageSourcePaths
	for decoder.More() {
		if len(result) >= workarchive.MaximumReplicas {
			return nil, errors.New("too many lineage sources")
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
			return nil, errors.New("each lineage source must be an object")
		}
		var source pruneLineageSourcePaths
		seen := make(map[string]bool, 9)
		for decoder.More() {
			token, err := decoder.Token()
			name, valid := token.(string)
			if err != nil || !valid || seen[name] {
				return nil, errors.New("duplicate or invalid lineage source field")
			}
			seen[name] = true
			var text *string
			var number *uint64
			switch name {
			case "assignment_id":
				text = &source.AssignmentID
			case "journal":
				text = &source.Journal
			case "checkpoint":
				text = &source.Checkpoint
			case "checkpoint_id":
				text = &source.CheckpointID
			case "manifest":
				text = &source.Manifest
			case "initial_receipt":
				text = &source.InitialReceipt
			case "maximum_challenge_lifetime":
				number = &source.MaximumChallengeLifetime
			case "maximum_proof_age":
				number = &source.MaximumProofAge
			case "maximum_renewal_term":
				number = &source.MaximumRenewalTerm
			default:
				return nil, fmt.Errorf("unknown lineage source field %q", name)
			}
			value, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			if text != nil {
				value, ok := value.(string)
				if !ok || value == "" {
					return nil, fmt.Errorf("%s must be a nonempty string", name)
				}
				*text = value
			} else {
				value, ok := value.(json.Number)
				if !ok {
					return nil, fmt.Errorf("%s must be an unsigned integer", name)
				}
				parsed, err := strconv.ParseUint(string(value), 10, 64)
				if err != nil {
					return nil, err
				}
				*number = parsed
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 9 {
			return nil, errors.New("lineage source requires exactly all nine fields")
		}
		result = append(result, source)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || len(result) == 0 {
		return nil, errors.New("lineage sources must be a nonempty complete array")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after lineage sources")
	}
	return result, nil
}

func loadPruneLineageSources(ctx context.Context, inventory authoritystore.ArchivePruneInventory,
	paths []pruneLineageSourcePaths, metadataParent, inventoryFile, metadataFile, out string,
) ([]pruneLineageExtractInput, error) {
	if len(paths) != len(inventory.Policy.Assignments) {
		return nil, errors.New("lineage sources must match the exact inventory assignment set")
	}
	byID := make(map[types.Hash]pruneLineageSourcePaths, len(paths))
	for _, source := range paths {
		id, err := pruneExternalID("assignment_id", source.AssignmentID)
		if err != nil {
			return nil, err
		}
		if _, found := byID[id]; found {
			return nil, errors.New("duplicate lineage assignment ID")
		}
		byID[id] = source
	}
	inputs := make([]pruneLineageExtractInput, len(paths))
	files := []string{inventoryFile, metadataFile}
	remainingBytes := int64(workarchive.MaximumReceiptLineageBytes)
	// Resolve all placement and stat the complete manifest budget before reading
	// any of its potentially large bodies. Shared manifests count per source.
	for i, assignment := range inventory.Policy.Assignments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, _ := assignment.ID()
		path, found := byID[id]
		if !found {
			return nil, errors.New("missing pinned lineage assignment")
		}
		checkpointID, err := pruneExternalID("checkpoint_id", path.CheckpointID)
		if err != nil {
			return nil, err
		}
		path.Journal, err = canonicalPruneLineageDirectory(pruneLineageSourcePath(metadataParent, path.Journal))
		if err != nil {
			return nil, err
		}
		for _, field := range []*string{&path.Checkpoint, &path.Manifest, &path.InitialReceipt} {
			*field, _, err = canonicalPruneLineageFile(pruneLineageSourcePath(metadataParent, *field))
			if err != nil {
				return nil, err
			}
			files = append(files, *field)
		}
		info, err := os.Lstat(path.Manifest)
		if err != nil || info.Size() <= 0 || info.Size() > workarchive.MaximumManifestBytes || info.Size() > remainingBytes {
			return nil, errors.Join(errors.New("aggregate lineage manifest budget exceeded"), err)
		}
		remainingBytes -= info.Size()
		inputs[i] = pruneLineageExtractInput{paths: path, source: authoritystore.ArchivePruneLineageSource{
			AssignmentID: id, JournalPath: path.Journal, CheckpointID: checkpointID,
			Policy: workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), assignment.Auditors...),
				MaximumChallengeLifetime: path.MaximumChallengeLifetime, MaximumProofAge: path.MaximumProofAge,
				MaximumRenewalTerm: path.MaximumRenewalTerm}}}
	}
	for i, input := range inputs {
		if workarchive.CustodyEvidencePathsOverlap(filepath.Dir(out), input.paths.Journal) {
			return nil, errors.New("evidence parent and source journals must be disjoint")
		}
		for j := 0; j < i; j++ {
			if workarchive.CustodyEvidencePathsOverlap(input.paths.Journal, inputs[j].paths.Journal) {
				return nil, errors.New("lineage source journals must be disjoint")
			}
		}
		for _, file := range files {
			if workarchive.CustodyEvidencePathsOverlap(input.paths.Journal, file) {
				return nil, errors.New("lineage input files must be outside source journals")
			}
		}
	}
	for _, file := range files {
		if workarchive.CustodyEvidencePathsOverlap(filepath.Dir(out), file) {
			return nil, errors.New("evidence parent must be dedicated and disjoint from input files")
		}
	}
	if err := rejectPruneLineageOutputAlias(out, files); err != nil {
		return nil, err
	}
	remainingEntries := uint64(workarchive.MaximumReceiptLineageEntries)
	for i := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input := &inputs[i]
		encoded, err := readRegularArtifact(input.paths.Checkpoint, workarchive.MaximumCustodyCheckpointBytes)
		if err != nil {
			return nil, err
		}
		input.source.Checkpoint, err = workarchive.DecodeCustodyCheckpoint(encoded)
		if err != nil {
			return nil, err
		}
		id, err := input.source.Checkpoint.ID()
		if err != nil || id != input.source.CheckpointID || input.source.Checkpoint.Artifacts != (workarchive.CustodyCheckpointTree{}) || input.source.Checkpoint.Sequence > remainingEntries {
			return nil, errors.Join(authoritystore.ErrPruneLineageEvidence, err)
		}
		remainingEntries -= input.source.Checkpoint.Sequence
	}
	remainingManifestBytes := workarchive.MaximumReceiptLineageBytes
	for i := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input := &inputs[i]
		encoded, err := readRegularArtifact(input.paths.Manifest, min(workarchive.MaximumManifestBytes, remainingManifestBytes))
		if err != nil {
			return nil, err
		}
		remainingManifestBytes -= len(encoded)
		manifest, err := workarchive.DecodeManifest(encoded)
		if err != nil {
			return nil, err
		}
		canonical, err := manifest.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, encoded) {
			return nil, errors.Join(authoritystore.ErrPruneLineageEvidence, err)
		}
		input.source.Manifest = encoded
		encoded, err = readRegularArtifact(input.paths.InitialReceipt, workarchive.MaximumReplicaReceiptBytes)
		if err != nil {
			return nil, err
		}
		input.source.InitialReceipt, err = workarchive.DecodeReplicaReceipt(encoded)
		if err != nil {
			return nil, err
		}
		canonical, err = input.source.InitialReceipt.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, encoded) {
			return nil, errors.Join(authoritystore.ErrPruneLineageEvidence, err)
		}
	}
	return inputs, nil
}

func pruneLineageSourcePath(parent, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(parent, path)
}

func canonicalPruneLineageDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() {
		return "", errors.Join(errors.New("lineage path requires an existing real directory"), err)
	}
	return filepath.EvalSymlinks(abs)
}

func canonicalPruneLineageFile(path string) (string, os.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, errors.Join(errors.New("lineage input requires an existing regular file"), err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	return canonical, info, err
}

func canonicalPruneLineageOutput(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := canonicalPruneLineageDirectory(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	out := filepath.Join(parent, filepath.Base(abs))
	if info, err := os.Lstat(out); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("existing evidence target must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return out, nil
}

func rejectPruneLineageOutputAlias(out string, inputs []string) error {
	output, err := os.Lstat(out)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, path := range inputs {
		input, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if os.SameFile(output, input) {
			return errors.New("evidence target aliases an input file")
		}
	}
	return nil
}

func pruneLineageExtractionReview(inventoryID, policyID, evidenceID types.Hash,
	inventoryFile, metadataFile, out string, inputs []pruneLineageExtractInput,
) types.Hash {
	encoder := codec.NewEncoder(256)
	encoder.U16(0)
	for _, id := range []types.Hash{inventoryID, policyID, evidenceID} {
		encoder.Fixed(id[:])
	}
	for _, path := range []string{inventoryFile, metadataFile, out} {
		encoder.BytesField([]byte(path))
	}
	encoder.U16(uint16(len(inputs)))
	for _, input := range inputs {
		encoder.Fixed(input.source.AssignmentID[:])
		encoder.Fixed(input.source.CheckpointID[:])
		for _, path := range []string{input.paths.Journal, input.paths.Checkpoint, input.paths.Manifest, input.paths.InitialReceipt} {
			encoder.BytesField([]byte(path))
		}
	}
	return types.DomainHash(pruneLineageExtractReviewDomain, encoder.Bytes())
}
