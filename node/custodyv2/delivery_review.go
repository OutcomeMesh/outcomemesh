package custodyv2

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// AdmissionDeliveryReviewPlacement pins public local filesystem metadata for an
// operator review without opening an owner, acquiring a source decision, reading
// archive chunks or loading a key. Role zero selects an outbox without sources.
// A hash of paths and stamps is local review evidence, not a portable grant or
// protection against replacing all external enrollment pins.
func AdmissionDeliveryReviewPlacement(path string, role AdmissionDeliveryRole, sources Sources) (types.Hash, error) {
	path, e := canonical(path)
	if e != nil {
		return types.Hash{}, e
	}
	name := "admission-outbox-review"
	files := map[string]bool{}
	if role != 0 {
		name, e = admissionDeliveryRoleName(role)
		if e != nil {
			return types.Hash{}, e
		}
		sources, e = canonicalSources(sources, name)
		if e != nil {
			return types.Hash{}, e
		}
		if e := disjoint(path, sources); e != nil {
			return types.Hash{}, e
		}
		files = placementFiles(sources)
	} else if sources != (Sources{}) {
		return types.Hash{}, ErrAdmissionDelivery
	}
	files[filepath.Dir(path)] = true
	if _, e := os.Lstat(path); e == nil {
		files[path] = true
	} else if !errors.Is(e, os.ErrNotExist) {
		return types.Hash{}, e
	}
	p := placement{Role: name, Sources: sources, Files: map[string]fileStamp{}}
	for file := range files {
		info, e := os.Lstat(file)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return types.Hash{}, errors.Join(ErrAdmissionDelivery, e)
		}
		stamp, e := stampFile(info)
		if e != nil {
			return types.Hash{}, e
		}
		p.Files[file] = stamp
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/required/admission-delivery/cli/placement", raw), nil
}
