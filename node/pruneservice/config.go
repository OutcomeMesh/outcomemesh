// Package pruneservice owns one original service-bound Prune placement. Its
// signed public protocol never carries paths, private keys or storage handles.
package pruneservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumConfigBytes = 64 << 20
const domain = "OMESH/prune-service/owner/"

var (
	ErrOwner       = errors.New("isolated Prune owner refused operation")
	ErrHeld        = errors.New("isolated Prune attempt is held; explicit retained-outcome recovery is required")
	ErrPosition    = errors.New("isolated Prune position does not match the retained cursor or exact attempt")
	ErrUnsupported = errors.New("isolated Prune Unix transport requires Linux peer credentials")
)

type Identity struct {
	RootID             types.Hash
	Service, Transport [32]byte
	OwnerUID           uint32
}

// Config is private owner configuration. The base resources are retained
// explicitly by EncodeConfig; state.Memory is never serialized as an empty object.
type Config struct {
	Runtime        store.ScheduledPruneRuntimeConfig
	GuardURL       string
	Witnesses      []prunenet.Endpoint
	WitnessTimeout time.Duration
}

type configDisk struct {
	Version      uint16
	Config       Config
	StateVersion uint16
	Resources    []resource.Resource
}

type Snapshot struct {
	Descriptor wire.Descriptor
	Position   wire.Position
	Intent     *wire.Request
	Response   *wire.Response
}

func EncodeConfig(c Config) ([]byte, error) {
	if c.Runtime.Base.State == nil || c.Runtime.CollectPruneClaim != nil || c.Runtime.CollectPruneCandidate != nil || c.Runtime.ServiceIdentity != nil || custodyguard.ValidateURL(c.GuardURL) != nil || len(c.Witnesses) == 0 || len(c.Witnesses) > 16 {
		return nil, ErrOwner
	}
	for _, path := range append(originalPaths(c), c.GuardURL) {
		if !utf8.ValidString(path) {
			return nil, ErrOwner
		}
	}
	for _, endpoint := range c.Witnesses {
		if !utf8.ValidString(endpoint.Address) {
			return nil, ErrOwner
		}
	}
	d := configDisk{Config: c, StateVersion: c.Runtime.Base.State.CommitmentVersion(), Resources: c.Runtime.Base.State.Resources()}
	d.Config.Runtime.Base.State = nil
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > MaximumConfigBytes {
		return nil, errors.Join(ErrOwner, err)
	}
	return raw, nil
}

func originalPaths(c Config) []string {
	r := c.Runtime
	paths := []string{r.InventoryPath, r.ExecutorPath, r.ExecutorPinsPath, r.ChainPath, r.ChainPinsPath}
	for _, v := range r.Authorities {
		paths = append(paths, v.AuthorityPath, v.AuthorityPinsPath)
	}
	for _, v := range r.Sources {
		paths = append(paths, v.Directory, v.JournalPath)
	}
	return paths
}

func DecodeConfig(raw []byte) (Config, error) {
	var d configDisk
	if len(raw) == 0 || len(raw) > MaximumConfigBytes {
		return Config{}, ErrOwner
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil || decoder.Decode(new(any)) != io.EOF || d.Version != 0 || d.Config.Runtime.Base.State != nil {
		return Config{}, ErrOwner
	}
	s, err := state.NewVersion(d.Resources, d.StateVersion)
	if err != nil {
		return Config{}, err
	}
	d.Config.Runtime.Base.State = s
	b, err := EncodeConfig(d.Config)
	if err != nil || !bytes.Equal(raw, b) {
		return Config{}, ErrOwner
	}
	return d.Config, nil
}

func configID(c Config) (types.Hash, []byte, error) {
	raw, err := EncodeConfig(c)
	if err != nil {
		return types.Hash{}, nil, err
	}
	return types.DomainHash(domain+"configuration/v0", raw), raw, nil
}

func inventoryBinding(v store.ScheduledPruneInventory) (prunefence.Binding, error) {
	iid, err := v.ID()
	if err != nil || v.FencePolicy == nil || v.FencePolicy.Service == nil {
		return prunefence.Binding{}, ErrOwner
	}
	rid, _ := v.Request.ID()
	for _, replica := range v.Replicas {
		aid, _ := replica.Assignment.ID()
		if aid != v.Request.AssignmentID {
			continue
		}
		ticket, _ := replica.Admission.ID()
		op := workchain.CanonicalPruneOperation{ServiceEnrollmentID: v.Request.ServiceEnrollmentID, AssignmentID: aid, TicketID: ticket, ScheduleID: v.Request.ScheduleID, StorageID: v.Request.StorageID, Boundary: v.Request.Boundary}
		oid, err := op.FenceOperationID()
		if err != nil {
			return prunefence.Binding{}, err
		}
		return prunefence.Binding{RequestID: rid, AssignmentID: aid, OperationID: oid, InventoryID: iid, ExecutorBindingID: v.ExecutorBindingID, StoragePairID: v.StoragePairID}, nil
	}
	return prunefence.Binding{}, ErrOwner
}

func validateNetwork(c Config, d wire.Descriptor) error {
	scope, err := d.Policy.Scope(d.Binding.AssignmentID, d.Binding.RequestID)
	if err != nil {
		return err
	}
	if err := prunenet.Validate(scope, d.Transport, c.Witnesses, c.WitnessTimeout); err != nil {
		return err
	}
	service := d.Policy.Service
	for _, endpoint := range c.Witnesses {
		for _, role := range [][32]byte{service.Service, service.Issuer, service.Guard} {
			if endpoint.Transport == role {
				return ErrOwner
			}
		}
	}
	return nil
}

func validateInventory(v store.ScheduledPruneInventory, d wire.Descriptor) error {
	b, err := inventoryBinding(v)
	if err != nil || b != d.Binding {
		return ErrOwner
	}
	p, _ := v.FencePolicy.CanonicalBytes()
	want, _ := d.Policy.CanonicalBytes()
	if !bytes.Equal(p, want) {
		return ErrOwner
	}
	return nil
}
