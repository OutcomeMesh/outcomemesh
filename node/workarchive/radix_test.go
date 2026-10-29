package workarchive

import (
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveRejectsRadixScheduleBeforePublication(t *testing.T) {
	f := newArchiveFixture(t)
	p := f.parameters
	p.RadixActivationHeight = 10
	chain, e := workchain.New(f.base, p)
	if e != nil {
		t.Fatal(e)
	}
	defer chain.Close()
	blocks, e := f.source.MigrationBlocks(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	for _, b := range blocks {
		if _, _, e = chain.Commit(b, b.Header.Seal.Timestamp); e != nil {
			t.Fatal(e)
		}
	}
	if e = VerifyChain(f.checkpoint, f.policy, chain); e == nil {
		t.Fatal("checkpoint lacks scheduled commitment")
	}
	if _, e = VerifyArchiveDirectory(f.archivePath, f.checkpoint, f.policy, f.base, p, DefaultLimits()); e == nil {
		t.Fatal("archive adopted schedule absent from binding")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "uncreated")
	dst := filepath.Join(parent, "out")
	if _, e = RestoreDirectory(f.archivePath, dst, f.checkpoint, f.policy, f.base, p, DefaultLimits(), workchain.DefaultPolicy()); e == nil {
		t.Fatal("restore accepted schedule")
	}
	if _, e = os.Stat(parent); !os.IsNotExist(e) {
		t.Fatal("restore touched destination", e)
	}
	if _, _, e = ExportDirectory(dst, f.binding, chain, f.manifest.Anchor.ID, DefaultExportOptions()); e == nil {
		t.Fatal("export omitted schedule")
	}
	if _, _, e = ComposeDirectory(dst, f.archivePath, f.checkpoint, f.policy, f.base, p, chain, f.manifest.Anchor.ID, DefaultExportOptions()); e == nil {
		t.Fatal("compose omitted schedule")
	}
	if _, e = os.Stat(parent); !os.IsNotExist(e) {
		t.Fatal("created archive destination", e)
	}
}
