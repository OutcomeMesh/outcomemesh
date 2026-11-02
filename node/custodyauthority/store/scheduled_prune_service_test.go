package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneScheduledServicePreflightDoesNotWriteOrHoldOwners(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	c := f.config[0]
	host, client := completionHosts(t)
	i := scheduledDeliveryIntent(t, c, host, client)
	id, _ := i.ID()
	roots := []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, c.JournalPath}
	before := custodyCommandPathTrees(t, roots)
	s, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Addresses() != nil || !reflect.DeepEqual(before, custodyCommandPathTrees(t, roots)) {
		t.Fatal("preflight created transport or changed original files")
	}
	if scheduledOperatorReview(t, c).Review.AlreadyApplied {
		t.Fatal("preflight applied command")
	}
	for _, field := range []string{"review", "binding", "intent", "other-replica-role"} {
		bad, expected := i, id
		switch field {
		case "review":
			bad.ReviewID = testHash(240)
		case "binding":
			bad.ExecutorBindingID = testHash(240)
		case "other-replica-role":
			key := f.plan.Replicas[1].Assignment.ReplicaPublicKey
			bad.ClientPeerID, _ = transport.PeerIDFromPublicKey(key[:])
		}
		if field != "intent" {
			expected, _ = bad.ID()
		} else {
			expected = testHash(240)
		}
		if got, err := PrepareScheduledPruneCommandService(t.Context(), c, bad, expected, time.Second); err == nil {
			got.Close()
			t.Fatal("preflight accepted substituted pin", field)
		}
	}
	if !reflect.DeepEqual(before, custodyCommandPathTrees(t, roots)) {
		t.Fatal("rejected preflight changed roots")
	}
	if err := s.Start(t.Context(), testKey(47), libp2ptransport.DefaultConfig()); err == nil || s.Addresses() != nil {
		t.Fatal("wrong private key started service", err)
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrPruneServiceStarted) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, custodyCommandPathTrees(t, roots)) {
		t.Fatal("idle service changed owners")
	}
	if scheduledOperatorReview(t, c).Review.AlreadyApplied {
		t.Fatal("idle service applied command")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestPruneScheduledServiceCloseDrainsOriginalOwners(t *testing.T) {
	for _, cancelService := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "cancel"}[cancelService], func(t *testing.T) {
			f := newScheduledPruneOperatorFixture(t)
			c := f.config[0]
			host, client := completionHosts(t)
			i := scheduledDeliveryIntent(t, c, host, client)
			id, _ := i.ID()
			s, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer s.Close()
			defer unblock()
			s.hooks.at = func(stage string) error {
				if stage == "scheduled-command-before-apply" {
					close(reached)
					<-release
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := s.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			address := s.Addresses()[0]
			delivered := make(chan error, 1)
			go func() {
				_, err := client.DeliverScheduledPrune(t.Context(), address, i.ServerPeerID, i, 3*time.Second)
				delivered <- err
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("missing original-owner barrier")
			}
			if cancelService {
				cancel()
			}
			closed := make(chan error, 2)
			go func() { closed <- s.Close() }()
			go func() { closed <- s.Close() }()
			select {
			case <-s.Done():
				t.Fatal("close escaped owner operation")
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{}); !errors.Is(err, ErrBusy) {
				t.Fatal("shutdown released active owners", err)
			}
			unblock()
			first, second := awaitScheduledDelivery(t, closed), awaitScheduledDelivery(t, closed)
			if first != second {
				t.Fatal("close lost retained result", first, second)
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("close did not finish")
			}
			if err := awaitScheduledDelivery(t, delivered); !errors.Is(err, scheduledwire.ErrUnconfirmed) {
				t.Fatal("shutdown asserted delivery", err)
			}
			// Shutdown before application leaves the old work and the signed intent
			// available for an explicit cold restart, not an implicit resume.
			if got := scheduledOperatorReview(t, c); got.Review.AlreadyApplied || got.Review.Authority.Authority.Pending != f.before[0].Authority.Pending {
				t.Fatal("shutdown changed accounting")
			}
			next, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if err := next.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeliverScheduledPrune(t.Context(), next.Addresses()[0], i.ServerPeerID, i, 3*time.Second); err != nil {
				t.Fatal(err)
			}
			got := scheduledOperatorReview(t, c)
			if !got.Review.AlreadyApplied || got.Review.Authority.Authority.Pending != f.before[0].Authority.Pending+1 {
				t.Fatal("cold retry lost old work")
			}
		})
	}
}

func TestPruneScheduledServiceUncertainWriteStopsAndRequiresLocalResume(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	c := f.config[0]
	host, client := completionHosts(t)
	i := scheduledDeliveryIntent(t, c, host, client)
	id, _ := i.ID()
	s, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fault := errors.New("independent confirmation unavailable")
	s.hooks.at = func(stage string) error {
		if stage == "confirm-before-publish" {
			return fault
		}
		return nil
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeliverScheduledPrune(t.Context(), s.Addresses()[0], i.ServerPeerID, i, 3*time.Second); !errors.Is(err, scheduledwire.ErrUnconfirmed) {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("uncertain service kept accepting")
	}
	if err := s.Close(); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
		t.Fatal("failure lost at shutdown", err)
	}
	before := scheduledOperatorReview(t, c)
	if next, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, 3*time.Second); err == nil {
		next.Close()
		t.Fatal("preflight resumed uncertain write")
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
		t.Fatal("preflight changed pending state")
	}
	if _, err := RunScheduledPruneCommand(t.Context(), c, "resume", before.Review.ReviewID); err != nil {
		t.Fatal(err)
	}
	next, err := PrepareScheduledPruneCommandService(t.Context(), c, i, id, 3*time.Second)
	if err != nil {
		t.Fatal("historical preflight rejected explicit recovery", err)
	}
	defer next.Close()
}
