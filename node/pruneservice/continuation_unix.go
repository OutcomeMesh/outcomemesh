//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

type retainedPrefix struct {
	exists bool
	raw    []byte
	stamp  types.Hash
}

func (o *Owner) prefix(name string, limit int) (retainedPrefix, error) {
	p := filepath.Join(o.root, "events", name)
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return retainedPrefix{}, nil
	} else if err != nil {
		return retainedPrefix{}, err
	}
	stamp, err := custodygateway.PlacementID(p, false)
	if err != nil {
		return retainedPrefix{}, err
	}
	raw, err := privateRead(p, limit)
	if err != nil {
		return retainedPrefix{}, err
	}
	if err = o.capture("events/" + name); err != nil {
		return retainedPrefix{}, err
	}
	if o.stamps["events/"+name] != stamp {
		return retainedPrefix{}, ErrOwner
	}
	return retainedPrefix{true, raw, stamp}, nil
}

func (o *Owner) continuationReview(q wire.Request, before wire.Position, name string, prefix retainedPrefix, target []byte) (ContinuationReview, error) {
	if !prefix.exists && name == "intent" || !bytes.HasPrefix(target, prefix.raw) {
		return ContinuationReview{}, ErrHeld
	}
	if err := o.checkFiles(); err != nil {
		return ContinuationReview{}, err
	}
	names := make([]string, 0, len(o.stamps))
	for n := range o.stamps {
		names = append(names, n)
	}
	sort.Strings(names)
	e := codec.NewEncoder(4096)
	e.Fixed(o.identity.RootID[:])
	for _, n := range names {
		e.BytesField([]byte(n))
		h := o.stamps[n]
		e.Fixed(h[:])
	}
	r := ContinuationReview{DescriptorID: q.DescriptorID, Before: before, Record: name, Exists: prefix.exists, FileID: prefix.stamp,
		OwnerFilesID: types.DomainHash(domain+"continuation-files/v0", e.Bytes()), PrefixID: types.DomainHash(domain+"continuation-prefix/v0", prefix.raw),
		TargetID: types.DomainHash(domain+"continuation-target/v0", target), RetainedBytes: uint32(len(prefix.raw)), TargetBytes: uint32(len(target))}
	r.RequestID, _ = q.ID()
	_, err := r.ID()
	return r, err
}

// A complete externally retained request is mandatory even for a short prefix.
// Completing its record creates a held intent; it never creates a live session.
func (o *Owner) withContinuation(ctx context.Context, before wire.Position, q wire.Request, use func(ContinuationReview, []byte, retainedPrefix) error) error {
	if !before.Valid() || q.Authorize(o.descriptor) != nil {
		return ErrPosition
	}
	ip, _ := q.IntentPosition()
	if before.Sequence == 1 && before != ip {
		return ErrPosition
	}
	intent, err := o.prefix("intent", wire.RequestBytes)
	if err != nil {
		return err
	}
	result, err := o.prefix("result", wire.MaximumResponseBytes)
	if err != nil {
		return err
	}
	qraw, _ := q.CanonicalBytes()
	if !intent.exists || !bytes.HasPrefix(qraw, intent.raw) {
		return ErrHeld
	}
	apply := func(name string, p retainedPrefix, target []byte) error {
		r, err := o.continuationReview(q, before, name, p, target)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		return use(r, target, p)
	}
	if len(intent.raw) != len(qraw) {
		if result.exists || before.Sequence == 2 {
			return ErrHeld
		}
		return apply("intent", intent, qraw)
	}
	if result.exists {
		if r, err := wire.DecodeResponse(result.raw); err == nil && r.Verify(o.descriptor, q) == nil {
			pos, _ := r.Position()
			if before.Sequence == 2 && before != pos {
				return ErrPosition
			}
			return apply("result", result, result.raw)
		}
	}
	if before.Sequence == 2 {
		return ErrPosition
	}
	_, err = o.withRetainedResponse(ctx, q, func(r wire.Response) (wire.Response, error) {
		r.DescriptorID = q.DescriptorID
		r.RequestID, _ = q.ID()
		r, err := r.Sign(o.descriptor, q, o.key)
		if err != nil {
			return wire.Response{}, err
		}
		target, err := r.CanonicalBytes()
		if err != nil {
			return wire.Response{}, err
		}
		return r, apply("result", result, target)
	})
	return err
}

func ReviewContinuation(ctx context.Context, root string, did types.Hash, before wire.Position, q wire.Request) (review ContinuationReview, returnErr error) {
	o, err := openConfigured(ctx, root, did)
	if err != nil {
		return review, err
	}
	defer func() { returnErr = errors.Join(returnErr, o.Close()) }()
	err = o.withContinuation(ctx, before, q, func(r ContinuationReview, _ []byte, _ retainedPrefix) error { review = r; return nil })
	return review, err
}

func Continue(ctx context.Context, root string, did types.Hash, before wire.Position, q wire.Request, expected types.Hash) (Snapshot, error) {
	return continuePublication(ctx, root, did, before, q, expected, ownerHooks{})
}
func continuePublication(ctx context.Context, root string, did types.Hash, before wire.Position, q wire.Request, expected types.Hash, hooks ownerHooks) (snapshot Snapshot, returnErr error) {
	if expected.IsZero() {
		return snapshot, ErrPosition
	}
	o, err := openConfigured(ctx, root, did)
	if err != nil {
		return snapshot, err
	}
	defer func() { returnErr = errors.Join(returnErr, o.Close()) }()
	err = o.withContinuation(ctx, before, q, func(r ContinuationReview, target []byte, p retainedPrefix) error {
		id, err := r.ID()
		if err != nil || id != expected {
			return ErrPosition
		}
		path := filepath.Join(root, "events", r.Record)
		if p.exists {
			err = appendOriginal(path, p, target, hooks, r.Record)
		} else {
			err = publishWithHooks(path, target, hooks, r.Record)
		}
		if err != nil {
			return errors.Join(ErrHeld, err)
		}
		if err = o.capture("events/" + r.Record); err != nil {
			return err
		}
		if err = o.loadEvents(); err != nil {
			return err
		}
		if err = o.check(); err != nil {
			return err
		}
		snapshot = Snapshot{Descriptor: o.descriptor, Position: o.position, Intent: o.intent}
		if len(o.response) > 0 {
			v, err := wire.DecodeResponse(o.response)
			if err != nil {
				return err
			}
			snapshot.Response = &v
		}
		return nil
	})
	return snapshot, err
}

// Append to the reviewed inode only. A second interrupted append requires a new
// review of its longer prefix; neither suffix replacement nor truncation exists.
func appendOriginal(path string, p retainedPrefix, target []byte, h ownerHooks, stage string) error {
	if !p.exists || !bytes.HasPrefix(target, p.raw) {
		return ErrOwner
	}
	stamp, err := custodygateway.PlacementID(path, false)
	if err != nil || stamp != p.stamp {
		return ErrPosition
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	a, e := f.Stat()
	b, e2 := os.Lstat(path)
	if e != nil || e2 != nil || !os.SameFile(a, b) || a.Size() != int64(len(p.raw)) {
		return ErrPosition
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(len(p.raw))+1))
	if e != nil || !bytes.Equal(raw, p.raw) {
		return ErrPosition
	}
	stamp, e = custodygateway.PlacementID(path, false)
	if e != nil || stamp != p.stamp {
		return ErrPosition
	}
	ok = true
	return syncPublication(f, path, target[len(p.raw):], h, stage)
}
