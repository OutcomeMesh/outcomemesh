package tieproducer

import (
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

// PublishCampaignCheckpoint is an explicit external publisher action, not part
// of coordinator production. The caller must independently approve both IDs
// and use an existing, trusted-owner publication directory separate from the
// coordinator's artifacts. A valid signature alone is not that approval.
//
// The immutable checkpoint is synced first; only then is the complete marker
// synced and linked into place without replacement. Readers may see a missing
// publication while staging, but never a partly written final file. Exact
// retries are safe; conflicting or malformed existing files are not repaired.
// An error after linking can leave a visible publication: retry the exact IDs.
// This does not protect against directory-owner tampering or storage rollback.
func PublishCampaignCheckpoint(
	directory string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
	checkpoint calibration.TiePairCheckpoint,
	expectedCheckpointID types.Hash,
) error {
	return publishCampaignCheckpoint(
		directory, plan, binding, expectedPlanID, checkpoint, expectedCheckpointID,
		writeImmutableCampaignFile,
	)
}

func publishCampaignCheckpoint(
	directory string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
	checkpoint calibration.TiePairCheckpoint,
	expectedCheckpointID types.Hash,
	writeImmutable func(string, []byte, int) error,
) error {
	if directory == "" || expectedPlanID.IsZero() || expectedCheckpointID.IsZero() || writeImmutable == nil {
		return ErrCampaignConfig
	}
	// ID verifies the plan, its external binding and ID, the slot, and signature
	// before any filesystem mutation. Never derive the approval pin here.
	identifier, err := checkpoint.ID(plan, binding, expectedPlanID)
	if err != nil {
		return err
	}
	if identifier != expectedCheckpointID {
		return ErrCampaignState
	}
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrCampaignConfig
	}
	name := campaignSequenceName(checkpoint.Sequence)
	if err := writeImmutable(
		filepath.Join(directory, name+".omtcp"), checkpoint.CanonicalBytes(),
		calibration.TiePairCheckpointBytes,
	); err != nil {
		return err
	}
	return writeImmutable(
		filepath.Join(directory, name+".published"), []byte(identifier.String()+"\n"),
		MaximumCampaignPublicationBytes,
	)
}
