//go:build linux || darwin

package pruneservice

import (
	"path/filepath"
	"slices"

	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

// Relabel only private filesystem locations. The persisted, descriptor-bound
// configuration supplies all other runtime inputs and remains byte-identical.
func relocatedConfig(c Config, b TransferBundle) (Config, error) {
	if b == (TransferBundle{}) {
		return c, nil
	}
	for _, base := range []string{b.Source, b.Destination} {
		if !filepath.IsAbs(base) || filepath.Clean(base) != base {
			return Config{}, ErrOwner
		}
	}
	if nested(b.Source, b.Destination) || nested(b.Destination, b.Source) {
		return Config{}, ErrOwner
	}
	c.Runtime.Authorities = slices.Clone(c.Runtime.Authorities)
	c.Runtime.Sources = slices.Clone(c.Runtime.Sources)
	for _, p := range runtimePaths(&c.Runtime) {
		if !filepath.IsAbs(*p) || filepath.Clean(*p) != *p || *p == b.Source || !nested(b.Source, *p) {
			return Config{}, ErrOwner
		}
		rel, err := filepath.Rel(b.Source, *p)
		if err != nil {
			return Config{}, err
		}
		*p = filepath.Join(b.Destination, rel)
	}
	return c, nil
}

func (o *Owner) originalReview(r store.ScheduledPruneReview) (store.ScheduledPruneReview, error) {
	if o.originalConfig == nil {
		return r, nil
	}
	return r.ReviewAtOriginalPlacement(o.originalConfig.Runtime, o.inventory)
}
