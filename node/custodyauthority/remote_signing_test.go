package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func remoteTestAssignment(t testing.TB) Assignment {
	t.Helper()
	a, err := WithRemoteParticipant(testAssignment(), testPublic(7), testPublic(8))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func remoteTestEntry(t testing.TB, state *State, kind Kind, purpose Purpose, actor byte, operation, ticket, evidence types.Hash) Entry {
	t.Helper()
	s := testSnapshot(t, state)
	c, err := (Command{Version: Version1, AssignmentID: s.AssignmentID, ExpectedSequence: s.Sequence, ExpectedHead: s.HeadID,
		Kind: kind, Purpose: purpose, OperationID: operation, TicketID: ticket, EvidenceID: evidence}).Sign(testKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func remoteTestReviewedEntry(t testing.TB, a Assignment, draft Command) Entry {
	t.Helper()
	review, err := RemoteCommandReviewID(a, draft)
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignReviewedRemoteCommand(a, draft, review, testKey(7))
	if err != nil {
		t.Fatal(err)
	}
	review, err = RemoteEntryReviewID(a, c)
	if err != nil {
		t.Fatal(err)
	}
	e, err := CosignReviewedRemoteCommand(a, c, review, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func remoteTestBegin(t testing.TB, a Assignment, state *State, serve Entry, plan types.Hash) Entry {
	t.Helper()
	s := testSnapshot(t, state)
	draft, err := BuildRemoteBeginCommand(a, serve, plan, Position{s.Sequence, s.HeadID})
	if err != nil {
		t.Fatal(err)
	}
	return remoteTestReviewedEntry(t, a, draft)
}

func remoteTestDrain(t testing.TB, a Assignment, state *State, begin Entry, tombstone types.Hash) Entry {
	t.Helper()
	s := testSnapshot(t, state)
	draft, err := BuildRemoteDrainedCommand(a, begin, tombstone, Position{s.Sequence, s.HeadID})
	if err != nil {
		t.Fatal(err)
	}
	return remoteTestReviewedEntry(t, a, draft)
}

func remoteTestHistory(t testing.TB) (Assignment, []Entry, Snapshot) {
	t.Helper()
	a := remoteTestAssignment(t)
	state := testState(t, a)
	var history []Entry
	apply := func(entry Entry) types.Hash { history = append(history, entry); return applyTestEntry(t, state, entry) }
	audit := apply(remoteTestEntry(t, state, Admit, Audit, 4, testHash(70), types.Hash{}, types.Hash{}))
	serve := remoteTestEntry(t, state, Admit, Serve, 5, testHash(71), types.Hash{}, types.Hash{})
	serveID := apply(serve)
	begin := remoteTestBegin(t, a, state, serve, testHash(72))
	apply(begin)
	apply(remoteTestDrain(t, a, state, begin, testHash(73)))
	apply(remoteTestEntry(t, state, Complete, 0, 4, types.Hash{}, audit, testHash(74)))
	apply(remoteTestEntry(t, state, Complete, 0, 5, types.Hash{}, serveID, testHash(75)))
	stop := apply(remoteTestEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(76)))
	apply(remoteTestEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop))
	return a, history, testSnapshot(t, state)
}

func TestRemoteAuthorityAssignmentOptInAndKeySeparation(t *testing.T) {
	v0 := testAssignment()
	a := remoteTestAssignment(t)
	v0ID, _ := v0.ID()
	id, _ := a.ID()
	if a.Version != Version1 || id == v0ID || a.RemoteControlPublicKey != testPublic(7) || a.RemoteTransportPublicKey != testPublic(8) {
		t.Fatal("not a fresh opt-in scope", a)
	}
	b0, _ := v0.CanonicalBytes()
	b, _ := a.CanonicalBytes()
	if len(b) != len(b0)+64 || !bytes.Equal(b[len(b)-64:len(b)-32], a.RemoteControlPublicKey[:]) || !bytes.Equal(b[len(b)-32:], a.RemoteTransportPublicKey[:]) {
		t.Fatal("V1 role keys were not appended canonically")
	}
	decoded, err := DecodeAssignment(b)
	if err != nil || !reflect.DeepEqual(decoded, a) {
		t.Fatal("V1 assignment roundtrip", err)
	}
	if _, err := WithRemoteParticipant(a, testPublic(9), testPublic(10)); !errors.Is(err, ErrAssignment) {
		t.Fatal("V1 silently reconfigured", err)
	}
	for _, existing := range [][32]byte{{}, v0.AuthorityPublicKey, v0.ReplicaPublicKey, v0.Auditors[0], v0.Consumers[0].PublicKey, v0.Consumers[1].PublicKey, v0.Consumers[2].PublicKey, testPublic(8)} {
		if _, err := WithRemoteParticipant(v0, existing, testPublic(8)); !errors.Is(err, ErrAssignment) {
			t.Fatal("remote control key alias accepted", err)
		}
	}
	for _, existing := range [][32]byte{{}, v0.AuthorityPublicKey, v0.ReplicaPublicKey, v0.Auditors[0], v0.Consumers[0].PublicKey, testPublic(7)} {
		if _, err := WithRemoteParticipant(v0, testPublic(7), existing); !errors.Is(err, ErrAssignment) {
			t.Fatal("remote transport key alias accepted", err)
		}
	}
	v0.RemoteControlPublicKey = testPublic(7)
	if _, err := v0.ID(); !errors.Is(err, ErrAssignment) {
		t.Fatal("hidden V0 remote role accepted", err)
	}
	input := testAssignment()
	detached, err := WithRemoteParticipant(input, testPublic(7), testPublic(8))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := detached.ID()
	input.Auditors[0], input.Consumers[0].PublicKey = testPublic(100), testPublic(101)
	after, _ := detached.ID()
	if before != after {
		t.Fatal("factory retained caller slices")
	}
}

func TestRemoteAuthorityIntrinsicFreezeAndExactDrain(t *testing.T) {
	a := remoteTestAssignment(t)
	state := testState(t, a)
	auditEntry := remoteTestEntry(t, state, Admit, Audit, 4, testHash(81), types.Hash{}, types.Hash{})
	audit := applyTestEntry(t, state, auditEntry)
	serve := remoteTestEntry(t, state, Admit, Serve, 5, testHash(82), types.Hash{}, types.Hash{})
	serveID := applyTestEntry(t, state, serve)
	begin := remoteTestBegin(t, a, state, serve, testHash(83))
	beginID := applyTestEntry(t, state, begin)
	snapshot := testSnapshot(t, state)
	if snapshot.Remote == nil || snapshot.Remote.BeginEntryID != beginID || snapshot.Remote.TicketID != serveID || snapshot.Remote.PlanID != testHash(83) || snapshot.Remote.ChallengeID != serve.Command.OperationID || snapshot.Pending != 2 {
		t.Fatal("hold did not retain exact scope", snapshot)
	}
	snapshot.Remote.BeginEntryID = testHash(120)
	if testSnapshot(t, state).Remote.BeginEntryID != beginID {
		t.Fatal("remote observation mutated live state")
	}
	for _, entry := range []Entry{
		remoteTestEntry(t, state, Admit, Prune, 6, testHash(84), types.Hash{}, types.Hash{}),
		remoteTestEntry(t, state, Complete, 0, 4, types.Hash{}, audit, testHash(85)),
		remoteTestEntry(t, state, Complete, 0, 5, types.Hash{}, serveID, testHash(86)),
		remoteTestEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(87)),
		remoteTestEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, testHash(87)),
		remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(88), serveID, serve.Command.OperationID),
	} {
		denyTestEntry(t, state, entry, ErrRemoteActive)
	}
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteDrained, 0, 8, beginID, serveID, testHash(89)), ErrActor)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteDrained, 0, 7, testHash(90), serveID, testHash(89)), ErrOperation)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteDrained, 0, 7, beginID, audit, testHash(89)), ErrOperation)
	drain := remoteTestDrain(t, a, state, begin, testHash(89))
	drainID := applyTestEntry(t, state, drain)
	current := testSnapshot(t, state)
	if current.Remote != nil || current.Pending != 2 {
		t.Fatal("drain completed original tickets", current)
	}
	operation, ok := state.LookupOperation(testPublic(5), serve.Command.OperationID)
	if !ok || operation.RemoteBeginID != beginID || operation.RemoteDrainID != drainID || operation.RemotePlanID != testHash(83) || operation.RemoteTombstoneID != testHash(89) || !operation.CompletionID.IsZero() {
		t.Fatal("remote history not retained", operation)
	}
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(91), serveID, serve.Command.OperationID), ErrOperation)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteDrained, 0, 7, beginID, serveID, testHash(89)), ErrOperation)
	applyTestEntry(t, state, remoteTestEntry(t, state, Complete, 0, 4, types.Hash{}, audit, testHash(92)))
	applyTestEntry(t, state, remoteTestEntry(t, state, Complete, 0, 5, types.Hash{}, serveID, testHash(93)))
	operation, _ = state.LookupOperation(testPublic(5), serve.Command.OperationID)
	if operation.RemoteBeginID != beginID || operation.RemoteDrainID != drainID || operation.RemoteTombstoneID != testHash(89) {
		t.Fatal("completion erased remote history")
	}
}

func TestRemoteAuthorityRejectsWrongTicketActorChallengeAndVersion(t *testing.T) {
	a := remoteTestAssignment(t)
	state := testState(t, a)
	audit := applyTestEntry(t, state, remoteTestEntry(t, state, Admit, Audit, 4, testHash(100), types.Hash{}, types.Hash{}))
	serve := remoteTestEntry(t, state, Admit, Serve, 5, testHash(101), types.Hash{}, types.Hash{})
	serveID := applyTestEntry(t, state, serve)
	for _, actor := range []byte{1, 2, 3, 4, 5, 6, 8, 99} {
		denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, actor, testHash(102), serveID, serve.Command.OperationID), ErrActor)
	}
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(102), audit, testHash(100)), ErrOperation)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(102), testHash(111), serve.Command.OperationID), ErrOperation)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(102), serveID, testHash(111)), ErrOperation)
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteDrained, 0, 7, testHash(111), serveID, testHash(112)), ErrOperation)
	applyTestEntry(t, state, remoteTestEntry(t, state, Complete, 0, 5, types.Hash{}, serveID, testHash(112)))
	denyTestEntry(t, state, remoteTestEntry(t, state, RemoteBegin, Serve, 7, testHash(102), serveID, serve.Command.OperationID), ErrOperation)
	s := testSnapshot(t, state)
	legacy, err := (Command{Version: Version0, AssignmentID: s.AssignmentID, ExpectedSequence: s.Sequence, ExpectedHead: s.HeadID, Kind: Stop, EvidenceID: testHash(114)}).Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := SignEntry(legacy, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	denyTestEntry(t, state, entry, ErrAssignment)
	legacyState := testState(t, testAssignment())
	legacySnapshot := testSnapshot(t, legacyState)
	modern, err := (Command{Version: Version1, AssignmentID: legacySnapshot.AssignmentID, ExpectedHead: legacySnapshot.HeadID, Kind: Stop, EvidenceID: testHash(114)}).Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	entry, err = SignEntry(modern, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	denyTestEntry(t, legacyState, entry, ErrAssignment)
}

func TestRemoteAuthorityReplayEveryPrefixAndDrainCapacity(t *testing.T) {
	a, entries, final := remoteTestHistory(t)
	for prefix := 0; prefix <= len(entries); prefix++ {
		pin := Position{Sequence: uint64(prefix), HeadID: final.AssignmentID}
		if prefix != 0 {
			pin.HeadID, _ = entries[prefix-1].ID()
		}
		state, err := Replay(a, final.AssignmentID, entries[:prefix], pin)
		if err != nil {
			t.Fatal(prefix, err)
		}
		if (testSnapshot(t, state).Remote != nil) != (prefix == 3) {
			t.Fatal("replay released or invented hold", prefix)
		}
		for _, next := range entries[prefix:] {
			if err := state.Apply(next); err != nil {
				t.Fatal(prefix, err)
			}
		}
		if !reflect.DeepEqual(testSnapshot(t, state), final) {
			t.Fatal("remote replay diverged", prefix)
		}
	}
	a.MaximumOperations, a.MaximumPending = 2, 1
	state := testState(t, a)
	var history []Entry
	apply := func(e Entry) { history = append(history, e); applyTestEntry(t, state, e) }
	for i := byte(0); i < 2; i++ {
		serve := remoteTestEntry(t, state, Admit, Serve, 5, testHash(130+i), types.Hash{}, types.Hash{})
		apply(serve)
		ticket, _ := serve.ID()
		begin := remoteTestBegin(t, a, state, serve, testHash(140+i))
		apply(begin)
		apply(remoteTestDrain(t, a, state, begin, testHash(150+i)))
		apply(remoteTestEntry(t, state, Complete, 0, 5, types.Hash{}, ticket, testHash(160+i)))
	}
	stop := remoteTestEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(170))
	apply(stop)
	stopID, _ := stop.ID()
	apply(remoteTestEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stopID))
	s := testSnapshot(t, state)
	if s.Sequence != MaximumEntries(a) || s.Sequence != 10 || s.Pending != 0 || s.Phase != Retired {
		t.Fatal("remote transitions consumed drain reserve", s)
	}
	if _, err := Replay(a, s.AssignmentID, history, Position{s.Sequence, s.HeadID}); err != nil {
		t.Fatal("V1 history was bounded like V0", err)
	}
	if MaximumEntries(testAssignment()) != 10 || MaximumEntries(Assignment{Version: 99}) != 0 {
		t.Fatal("legacy/unknown entry budget changed")
	}
}

func TestRemoteReviewedSigningIsStaticAndRoleSeparated(t *testing.T) {
	a := remoteTestAssignment(t)
	state := testState(t, a)
	serve := remoteTestEntry(t, state, Admit, Serve, 5, testHash(180), types.Hash{}, types.Hash{})
	applyTestEntry(t, state, serve)
	s := testSnapshot(t, state)
	draft, err := BuildRemoteBeginCommand(a, serve, testHash(181), Position{s.Sequence, s.HeadID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRemoteBeginCommand(a, serve, testHash(181), Position{s.Sequence, testHash(190)}); !errors.Is(err, ErrHead) {
		t.Fatal("immediate post-admission position used an unrelated head", err)
	}
	if _, err := BuildRemoteBeginCommand(a, serve, testHash(181), Position{s.Sequence + 1, s.HeadID}); !errors.Is(err, ErrHead) {
		t.Fatal("later position reused the admission head", err)
	}
	before := draft
	id, err := RemoteCommandReviewID(a, draft)
	unsigned, _ := draft.unsignedBytes()
	if err != nil || id != types.DomainHash("OMESH/custody-authority/command/signature/v1", unsigned) || draft != before {
		t.Fatal("wrong remote signature message", err)
	}
	for _, key := range []ed25519.PrivateKey{nil, testKey(1), testKey(2), testKey(8)} {
		if _, err := SignReviewedRemoteCommand(a, draft, id, key); err == nil {
			t.Fatal("wrong remote signer role accepted")
		}
	}
	changed := draft
	changed.OperationID = testHash(182)
	if _, err := SignReviewedRemoteCommand(a, changed, id, testKey(7)); !errors.Is(err, ErrRemoteReview) {
		t.Fatal("stale remote review signed", err)
	}
	begin := remoteTestReviewedEntry(t, a, draft)
	if _, err := RemoteCommandReviewID(a, begin.Command); !errors.Is(err, ErrRemoteReview) {
		t.Fatal("existing B signature silently replaced", err)
	}
	if testSnapshot(t, state).Remote != nil {
		t.Fatal("static signing accepted hold")
	}
	beginID := applyTestEntry(t, state, begin)
	s = testSnapshot(t, state)
	if _, err := BuildRemoteDrainedCommand(a, begin, testHash(183), Position{s.Sequence + 1, beginID}); !errors.Is(err, ErrHead) {
		t.Fatal("drain position refreshed", err)
	}
	if _, err := BuildRemoteDrainedCommand(a, begin, testHash(183), Position{s.Sequence, testHash(184)}); !errors.Is(err, ErrHead) {
		t.Fatal("drain head refreshed", err)
	}
	if _, err := BuildRemoteBeginCommand(a, serve, testHash(181), Position{0, s.AssignmentID}); !errors.Is(err, ErrHead) {
		t.Fatal("begin preceded selected admission", err)
	}
	for _, kind := range []Kind{Admit, Complete} {
		c := Command{Version: Version1, AssignmentID: s.AssignmentID, ExpectedSequence: s.Sequence, ExpectedHead: s.HeadID, Kind: kind, ActorPublicKey: testPublic(4)}
		if kind == Admit {
			c.Purpose = Audit
			c.OperationID = testHash(185)
		} else {
			c.TicketID = beginID
			c.EvidenceID = testHash(185)
		}
		if _, err := CustodyCommandReviewID(a, c, Audit); !errors.Is(err, ErrCustodyReview) {
			t.Fatal("legacy custody review accepted V1", err)
		}
		c.ActorPublicKey = testPublic(6)
		if kind == Admit {
			c.Purpose = Prune
		}
		if _, err := PruneCommandReviewID(a, c); !errors.Is(err, ErrPruneReview) {
			t.Fatal("legacy prune review accepted V1", err)
		}
		if _, err := RemoteCommandReviewID(a, c); !errors.Is(err, ErrRemoteReview) {
			t.Fatal("remote review signed ordinary command", err)
		}
	}
}

func TestRemoteAuthorityV1DomainsAndCanonicalBytes(t *testing.T) {
	a, entries, _ := remoteTestHistory(t)
	b, _ := a.CanonicalBytes()
	id, _ := a.ID()
	if id != types.DomainHash("OMESH/custody-authority/assignment/id/v1", b) || id == types.DomainHash("OMESH/custody-authority/assignment/id/v0", b) {
		t.Fatal("V1 assignment used legacy domain")
	}
	for _, entry := range entries {
		eb, err := entry.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEntry(eb)
		if err != nil || decoded != entry || len(eb) != MaximumEntryBytes {
			t.Fatal("V1 fixed entry roundtrip", err)
		}
		cb, _ := entry.Command.CanonicalBytes()
		c, err := DecodeCommand(cb)
		if err != nil || c != entry.Command || len(cb) != MaximumCommandBytes {
			t.Fatal("V1 fixed command roundtrip", err)
		}
		entryID, _ := entry.ID()
		if entryID != types.DomainHash("OMESH/custody-authority/entry/id/v1", eb) {
			t.Fatal("V1 entry used legacy ID domain")
		}
		command := entry.Command
		unsigned, _ := command.unsignedBytes()
		wrong := types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned)
		actor := byte(7)
		switch command.Kind {
		case Admit:
			if command.Purpose == Audit {
				actor = 4
			} else {
				actor = 5
			}
		case Complete:
			if command.ActorPublicKey == testPublic(4) {
				actor = 4
			} else {
				actor = 5
			}
		case Stop, Retire:
			actor = 1
		}
		copy(command.Signature[:], ed25519.Sign(testKey(actor), wrong[:]))
		if _, err := command.CanonicalBytes(); !errors.Is(err, ErrCommand) {
			t.Fatal("V0 signature accepted for V1", err)
		}
		changed := entry
		unsigned, _ = changed.unsignedBytes()
		wrong = types.DomainHash("OMESH/custody-authority/entry/signature/v0", unsigned)
		copy(changed.Signature[:], ed25519.Sign(testKey(1), wrong[:]))
		if _, err := changed.CanonicalBytes(); !errors.Is(err, ErrEntry) {
			t.Fatal("V0 co-signature accepted for V1", err)
		}
		changed = entry
		changed.Version = Version0
		if _, err := changed.CanonicalBytes(); !errors.Is(err, ErrEntry) {
			t.Fatal("entry/command versions differ", err)
		}
	}
	for length := 0; length < len(b); length++ {
		if _, err := DecodeAssignment(b[:length]); err == nil {
			t.Fatal("truncated V1 assignment accepted", length)
		}
	}
	if _, err := DecodeAssignment(append(b, 0)); err == nil {
		t.Fatal("trailing V1 assignment byte accepted")
	}
}

func TestRemoteAuthorityV1GoldenHistory(t *testing.T) {
	a, entries, final := remoteTestHistory(t)
	b, _ := a.CanonicalBytes()
	id, _ := a.ID()
	if id.String() != "4f7596ad0e318749d6d1d47c55c50b1637315870470c41ec0367d9abb9248006" || len(b) != 515 || final.Sequence != 8 {
		t.Fatal("V1 canonical history shape changed")
	}
	want := []string{
		"73dfbd89e799b2d8e77e351a748a3451780a2aae6c8ab5c6538c87c91f04a1fc",
		"e87dcfc03c9762c032b917d18940387c3e5a1ebc8f01fa3543e2f34786549d72",
		"e1b8c76157010fbcf155233b519e5497b3d71f7fc18b3fd67dc487f517735a92",
		"1b07c6a6fcdd1efc534e12217b1ada9c6eb201ab6c1f372af048dd2451faa94e",
		"3fb4218736ac4b9d243bf610e91d6efdf936405f5d7775e33e9377325cbc8418",
		"34b036323e5004282a0a8960081cc2a369813b7eb5808188a651e70547dae277",
		"2156f53c31663b68f2416c2d33a78f006dced8369579731756f5215799ef56b8",
		"9ae890d3829b6932c491882d749e0cd1f1addb330ad966ed7b8544854beb6764",
	}
	for index, entry := range entries {
		entryID, _ := entry.ID()
		if entryID.String() != want[index] {
			t.Fatal("V1 golden entry changed", index, entryID)
		}
	}
}

func FuzzRemoteAuthorityCanonical(f *testing.F) {
	a, entries, _ := remoteTestHistory(f)
	b, _ := a.CanonicalBytes()
	f.Add(uint8(0), b)
	for _, entry := range entries {
		eb, _ := entry.CanonicalBytes()
		cb, _ := entry.Command.CanonicalBytes()
		f.Add(uint8(1), eb)
		f.Add(uint8(2), cb)
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, kind uint8, input []byte) {
		var output []byte
		var err error
		switch kind % 3 {
		case 0:
			var a Assignment
			a, err = DecodeAssignment(input)
			if err == nil {
				output, err = a.CanonicalBytes()
			}
		case 1:
			var e Entry
			e, err = DecodeEntry(input)
			if err == nil {
				output, err = e.CanonicalBytes()
			}
		case 2:
			var c Command
			c, err = DecodeCommand(input)
			if err == nil {
				output, err = c.CanonicalBytes()
			}
		}
		if err == nil && !bytes.Equal(input, output) {
			t.Fatal("noncanonical remote authority accepted")
		}
	})
}
