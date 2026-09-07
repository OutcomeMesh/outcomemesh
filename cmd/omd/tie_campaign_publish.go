package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

// This command is a separate publisher action. It reads only public inputs and
// network configuration; it does not open a chain or contact either peer.
func runWorkTelemetryTieCampaignPublish(arguments []string) error {
	flags := flag.NewFlagSet("work-telemetry-tie-campaign-publish", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "trusted network genesis and WorkGraph activation configuration")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "independently approved controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted coordinator Ed25519 public key")
	observerKeyText := flags.String("observer-public-key", "", "trusted plan observer Ed25519 public key")
	sequence := flags.Uint64("sequence", 0, "independently approved one-based slot sequence")
	inputPath := flags.String("input", "", "coordinator-signed checkpoint file to review and publish")
	checkpointIDText := flags.String("checkpoint-id", "", "independently approved checkpoint ID (never inferred from input)")
	publishedDirectory := flags.String("published", "", "existing trusted-owner external publication directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *planPath == "" || *planIDText == "" || *coordinatorKeyText == "" ||
		*observerKeyText == "" || *sequence == 0 || *inputPath == "" ||
		*checkpointIDText == "" || *publishedDirectory == "" {
		return errors.New("published plan and trusted keys, sequence, input checkpoint, independently approved checkpoint ID, and separate existing publication directory are required")
	}
	observerKey, err := parseHash(*observerKeyText)
	if err != nil {
		return fmt.Errorf("observer-public-key: %w", err)
	}
	checkpointID, err := parseHash(*checkpointIDText)
	if err != nil {
		return fmt.Errorf("checkpoint-id: %w", err)
	}
	plan, binding, planID, err := loadPublishedTiePlan(
		*data, *planPath, *planIDText, *coordinatorKeyText, observerKey,
	)
	if err != nil {
		return err
	}
	checkpoint, err := calibration.LoadTiePairCheckpointFile(*inputPath, plan, binding, planID, checkpointID)
	if err != nil {
		return err
	}
	if checkpoint.Sequence != *sequence {
		return errors.New("checkpoint sequence does not match the approved sequence")
	}
	inputDirectory, err := os.Stat(filepath.Dir(*inputPath))
	if err != nil {
		return err
	}
	publicationDirectory, err := os.Stat(*publishedDirectory)
	if err != nil {
		return err
	}
	if os.SameFile(inputDirectory, publicationDirectory) {
		return errors.New("checkpoint input and external publication directories must differ")
	}
	if err := tieproducer.PublishCampaignCheckpoint(
		*publishedDirectory, plan, binding, planID, checkpoint, checkpointID,
	); err != nil {
		return err
	}
	fmt.Printf("work_tie_campaign_published plan=%s sequence=%d pair=%s checkpoint=%s published=%s\n",
		planID, checkpoint.Sequence, checkpoint.PairID, checkpointID, *publishedDirectory)
	return nil
}
