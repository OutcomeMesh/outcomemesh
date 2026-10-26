package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// Retained canonical wire vector: independently signed Audit admission and
// original custody response. No randomized archive fixture is used by the codec golden.
const custodyTerminalGoldenHex = "4f4d434154524d3000005cecfc7d78898329af68793d5ac5281dcc99d059ad3dbba151e81d8c643467ddfe024f4d4341454e545200004f4d4341434d" +
	"4e4400005cecfc7d78898329af68793d5ac5281dcc99d059ad3dbba151e81d8c643467dd00000000000000005cecfc7d78898329af68793d5ac5281d" +
	"cc99d059ad3dbba151e81d8c643467dd0101bc3847a36479b01eaa568025067472043606817c4f1874fc7e2d8570afa51bc200000000000000000000" +
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ca93ac170518" +
	"7071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c549f42b76c526434390ba45a27de6f993dd781e6ada3d59264eefa4e133d1ee650ee" +
	"15499984589f88ea7476caca1eb3cf19f1122e599489cb9866be7b86f9068a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f" +
	"6f5c8391aaecd9ccd89df5c7a0a842b7e577fbdc5ad701289bc85c3d90bc02904fac45d0f1cbecef5c867fdfa0494179afdab81c89111fb8bec1e508" +
	"2a80bc521f098c024f4d4341494e543000005cecfc7d78898329af68793d5ac5281dcc99d059ad3dbba151e81d8c643467ddca93ac1705187071d67b" +
	"83c7ff0efe8108e8ec4530575d7726879333dbdabe7ced4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d120732cbcd238" +
	"1e6b88e98f6a627ee1a6224e0054e2274dc212b629569f3b10a600000000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000002d488142fcecc7512e27da3467a6b5d235728117de0d616854216d2af5b41247000000006adfcb57000000006adfcb93000000006ae0" +
	"196e00016ccd48cf1d6d0b63483dddd3c20a73036acf5bb36d70231e02e900efb4893608fa134f4d5741434a454e0000000000000000000100000000" +
	"00000000000000000000000000000000000000000000000000000000c6024f4d57415252435000000000004de39b90bb713ab28af6fb01e548668a1b" +
	"697f41b3b0cb26078f3d004105cfe375000000000000000a80269b83f4b07483ce3336a47875ff16f38caef5b98b896e5d77f9d927dc8c03b346a6f1" +
	"73bf59700e12e265d7a90c29942fcf23251bccfcf6c01aa459e42bdbb09a7455cedc16dce40025448c6ace03c3e9c0acba3bd3d5fc43dc84063eb9cc" +
	"0045cff97cb3c26769d1db3fb967d7769644fa99244a07b739702a03496abd7004678e9034d332207265f18a79c6c16b04e304f41a9e89b20a61ae62" +
	"5ad12563000000006adfcb4d000000006ae0196d70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9aea8b7ed1df333c262" +
	"b6c90c4a4c76ed562dc88c3ea14fb83d037ae11f7eec9c5d29472fb91c6c4e11588a8b625a40832b0995e0a05ec5f8bea8d1c1cfbd1bc907fe104f4d" +
	"5741435245430000a5024f4d57414348414c0000b346a6f173bf59700e12e265d7a90c29942fcf23251bccfcf6c01aa459e42bdbb09a7455cedc16dc" +
	"e40025448c6ace03c3e9c0acba3bd3d5fc43dc84063eb9cc2d488142fcecc7512e27da3467a6b5d235728117de0d616854216d2af5b4124700000000" +
	"6adfcb57000000006adfcb93000000006ae0196e6ccd48cf1d6d0b63483dddd3c20a73036acf5bb36d70231e02e900efb4893608000101fa1f549f53" +
	"77dbb43d48b3c4916e71fdede1cd0d3f9ae12b1f4ab0eeb5c0909fed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d12c" +
	"7980e07a97b6718056d80b50711e7a478669161653def76cc22b46ff4050d860ce3914a7176e6291c3560f2ce2eb7fe9f1460df365527595a0f4e998" +
	"805d09cf094f4d57414f4242540000b09a7455cedc16dce40025448c6ace03c3e9c0acba3bd3d5fc43dc84063eb9cc01fa1f549f5377dbb43d48b3c4" +
	"916e71fdede1cd0d3f9ae12b1f4ab0eeb5c0909f82094f4d574152424c4b00010000004d80269b83f4b07483ce3336a47875ff16f38caef5b98b896e" +
	"5d77f9d927dc8c0300000000000000000000000a03eb02000100000000004d000000000000000a80269b83f4b07483ce3336a47875ff16f38caef5b9" +
	"8b896e5d77f9d927dc8c03000000006553f100007986bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffde688a7e3502cfc2ce" +
	"9c832eee98e4cd3d107e0aafd1c5253a273e74f217f650990c602988fcb8dd153d8f37b328f9fd80247b008428e78d1f6371a0b84b114f052626f83b" +
	"e9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c00000000000000014ac1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845" +
	"230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a84a725e151beb9dd0fba579c14cc511895301f6a6" +
	"32142e7294f88f783891222531199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020d44be30322640c368aff4cf516cd220b" +
	"f70227f9f1558f65166116387cdd61ae00000000000000000000eb02000100000000004d000000000000000b003c3b9cc134425eee7b4efcb861bee7" +
	"25e2c5acff3f8951467566a983ff4c0c000000006553f13c007986bfffffffffffffffffffffffffffffffffffffffffffffffffffffffff5485e942" +
	"6c930ad0b6b82f90b9a92170b0c60a3069219288909eeae497ad885d2bb5b5492acf61a4b311e1d19323bfe99455358b064b26a2ab0a6ebc9d76d938" +
	"052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c0000000000000004d7c1265c23e8244ab55cbcaba33ab962f964a57c" +
	"a1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8c7c1fda97786822c470ed2eb7686ed" +
	"896181eee711616d60d299162e16139db231199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020e7fca00a0dec604f61cae5" +
	"fcd4179e9b3d9cf3686a12f546b738b885fbe2c1ed00000000000000000000eb02000100000000004d000000000000000c0039fa830049e54db10d8d" +
	"33accb6f496c018026c6160c51bf254c32a463eb82000000006553f178007986bfffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
	"ff57e44480e008de17516c0feb62eef16e65b7c08714b7974c45a8ac15e6893c567ee50589b234fafe36b3d20f909c3cc84190939bfb368ebdc40669" +
	"06948900a5052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c000000000000000535c1265c23e8244ab55cbcaba33ab9" +
	"62f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8e92900477272a3d20ad5" +
	"7fd7fdd7151026388f74f450c7abba2d4c0772c8753031199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020b2b4e7070af7" +
	"669aa6a81391dc7453e0c68904c84ec6b0ca3eee1444def4aff400000000000000000000f2014f4d57414350524600009e621f78f9a8e846375825d1" +
	"3ff42ddd16d212db5724130c90d6c88ba2c608642d488142fcecc7512e27da3467a6b5d235728117de0d616854216d2af5b41247b09a7455cedc16dc" +
	"e40025448c6ace03c3e9c0acba3bd3d5fc43dc84063eb9cc000000006adfcb58b2ad5cebdd0cfbfb363892406d9d4ee847159168b03fe0b9baee0292" +
	"0e538b9070df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae971ae01346cc319be6a330ed0ec5cd83fcb20e14084eb5eb" +
	"342ec6f7671f5333c6cf95577ccc2b8664f5c17bf3bcc79830ed197444fbf8b91af969b7e393780086034f4d57415252435000010000004de39b90bb" +
	"713ab28af6fb01e548668a1b697f41b3b0cb26078f3d004105cfe375000000000000000a80269b83f4b07483ce3336a47875ff16f38caef5b98b896e" +
	"5d77f9d927dc8c03b346a6f173bf59700e12e265d7a90c29942fcf23251bccfcf6c01aa459e42bdbb09a7455cedc16dce40025448c6ace03c3e9c0ac" +
	"ba3bd3d5fc43dc84063eb9cc0045cff97cb3c26769d1db3fb967d7769644fa99244a07b739702a03496abd7004678e9034d332207265f18a79c6c16b" +
	"04e304f41a9e89b20a61ae625ad125632d488142fcecc7512e27da3467a6b5d235728117de0d616854216d2af5b41247d6aa2e994d636ca63b228f4e" +
	"8b96b794c0e9f9344e6e27415af22baee0d5cd28000000006adfcb58000000006ae0196e70df9e2279adbec6d12bf2921184c9222eb24ed852005bf6" +
	"40139f52e59cd9ae3176755824b8c0de6702a49ff6c37fdeb4f4b607db173d497ae40ab633567ab08e30ee1cb4b8ec8b596c7f06e3f020f603e1468e" +
	"cabab4fba31d6f51fb934d0e"

func custodyTerminalGolden(t testing.TB) CustodyTerminal {
	t.Helper()
	b, err := hex.DecodeString(custodyTerminalGoldenHex)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := DecodeCustodyTerminal(b)
	if err != nil {
		t.Fatal(err)
	}
	return terminal
}

func TestCustodyTerminalCanonicalGoldenAndBounds(t *testing.T) {
	terminal := custodyTerminalGolden(t)
	b, err := terminal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := terminal.ID()
	const wantID = "7e2c187517a864f52745f742671eea0ecd87df89fe0289c012e7cae8fd8cd9cc"
	if len(b) != 3252 || hex.EncodeToString(id[:]) != wantID {
		t.Fatalf("terminal golden length=%d id=%x", len(b), id[:])
	}
	decoded, err := DecodeCustodyTerminal(b)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := decoded.CanonicalBytes()
	if !bytes.Equal(b, encoded) {
		t.Fatal("noncanonical roundtrip")
	}
	for _, invalid := range [][]byte{nil, b[:len(b)-1], append(append([]byte(nil), b...), 0), make([]byte, MaximumCustodyTerminalBytes+1)} {
		if _, err := DecodeCustodyTerminal(invalid); err == nil {
			t.Fatal("accepted malformed or oversized terminal")
		}
	}
	for _, offset := range []int{0, 8, 10, 43, len(b) - 1} {
		changed := append([]byte(nil), b...)
		changed[offset] ^= 1
		if _, err := DecodeCustodyTerminal(changed); err == nil {
			t.Fatal("accepted mutated terminal", offset)
		}
	}
}

func TestCustodyTerminalPinnedFilePublication(t *testing.T) {
	terminal := custodyTerminalGolden(t)
	id, _ := terminal.ID()
	path := filepath.Join(t.TempDir(), "terminal.omcat")
	for range 2 {
		if err := PublishCustodyTerminalFile(t.Context(), path, terminal); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadCustodyTerminalFile(path, id)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := loaded.ID()
		if got != id {
			t.Fatal("loaded wrong terminal")
		}
	}
	if _, err := LoadCustodyTerminalFile(path, types.Hash{}); err == nil {
		t.Fatal("loaded without independent pin")
	}
	if _, err := LoadCustodyTerminalFile(path, testHash(171)); err == nil {
		t.Fatal("loaded another evidence ID")
	}
	missing := filepath.Join(t.TempDir(), "missing", "terminal.omcat")
	if err := PublishCustodyTerminalFile(t.Context(), missing, terminal); err == nil {
		t.Fatal("created missing parent")
	}
	if _, err := os.Lstat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created missing parent", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := PublishCustodyTerminalFile(ctx, path, terminal); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
	if err := os.WriteFile(path, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PublishCustodyTerminalFile(t.Context(), path, terminal); err == nil {
		t.Fatal("replaced different existing evidence")
	}
	if b, _ := os.ReadFile(path); string(b) != "different" {
		t.Fatal("mutated existing evidence")
	}
}

func TestCustodyTerminalCaptureCurrentHeadAndIndependentTickets(t *testing.T) {
	f := newManagedAuditFixture(t)
	scope := custodyCommandTestScope(f)
	coordinator := f.serve.archive.f.coordinator
	config := CustodyTerminalCaptureConfig{Scope: scope, Admission: f.config.Admission,
		JournalPath: f.config.JournalPath, JournalLimits: f.config.JournalLimits}
	if _, err := CaptureCustodyTerminal(t.Context(), coordinator, config); err == nil {
		t.Fatal("captured uncommitted response")
	}
	entry, _, err := f.journal.Append(f.answer(t))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := CaptureCustodyTerminal(t.Context(), coordinator, config)
	if err != nil || terminal.Entry.Record.Proof.RespondedAt != entry.Record.Proof.RespondedAt {
		t.Fatal("capture changed original response", err)
	}
	before := testCoordination(t, coordinator).Authority
	draft, err := BuildCustodyCompleteCommand(scope, config.Admission, terminal, position(before))
	if err != nil {
		t.Fatal(err)
	}
	completion := custodyCommandTestSign(t, scope, draft, custodyauthority.Audit)
	appendCoordinated(t, coordinator, completion)
	if _, err := CaptureCustodyTerminal(t.Context(), coordinator, config); err == nil {
		t.Fatal("completed audit ticket remained a capture grant")
	}
	config.Admission = f.serve.config.Admission
	served, err := CaptureCustodyTerminal(t.Context(), coordinator, config)
	if err != nil {
		t.Fatal("audit completion also completed independent serve", err)
	}
	firstID, _ := terminal.ID()
	serveID, _ := served.ID()
	if firstID == serveID {
		t.Fatal("lost selected admission binding")
	}
	// A new valid record advances the source. The old result remains valid
	// historical evidence, but cannot be captured/applied as the current head.
	previous := entry.Record.RenewedReceipt
	challenge, err := workarchive.CreateCustodyChallenge(scope.Manifest, previous, testKey(3), f.serve.now+1, 60, 1, previous.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(f.serve.config.Objects, scope.Manifest, previous, challenge,
		scope.CustodyPolicy, f.serve.config.ReplicaPrivateKey, f.serve.now+2)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.RenewReplicaReceipt(scope.Manifest, previous, challenge, batch, proof,
		scope.CustodyPolicy, f.serve.config.ReplicaPrivateKey, f.serve.now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.journal.Append(workarchive.CustodyRecord{Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}); err != nil {
		t.Fatal(err)
	}
	if err := served.Validate(scope); err != nil {
		t.Fatal("historical response expired or changed", err)
	}
	if _, err := CaptureCustodyTerminal(t.Context(), coordinator, config); err == nil {
		t.Fatal("searched or promoted an older response under an advanced head")
	}
	decision, err := f.journal.AcquireDecision()
	if err != nil {
		t.Fatal(err)
	}
	defer decision.Close()
	if err := ValidateCustodyTerminalDecision(scope, served, decision); err == nil {
		t.Fatal("accepted old terminal against advanced source")
	}
}

func FuzzDecodeCustodyTerminal(f *testing.F) {
	terminal := custodyTerminalGolden(f)
	b, _ := terminal.CanonicalBytes()
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte("OMCATRM0"))
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := DecodeCustodyTerminal(input)
		if err != nil {
			return
		}
		encoded, err := decoded.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("accepted noncanonical terminal", err)
		}
	})
}
