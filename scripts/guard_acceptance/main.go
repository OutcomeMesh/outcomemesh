// Command guard_acceptance prepares fresh disposable public traffic and verifies
// guard replies for the isolated two-host deployment campaign. It never exports
// the subject's signing key and must not be used to provision real identities.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"os"
	"path/filepath"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	if len(os.Args) < 3 {
		panic("prepare DIR | verify IDENTITY REQUEST SEAL")
	}
	switch os.Args[1] {
	case "prepare":
		d := os.Args[2]
		must(os.Mkdir(d, 0700))
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(e)
		defer clear(key)
		var p [32]byte
		copy(p[:], pub)
		raw, e := json.Marshal(guard.Config{Subjects: [][32]byte{p}, Limit: 4})
		must(e)
		must(os.WriteFile(filepath.Join(d, "config.json"), raw, 0600))
		raw, e = json.Marshal(guard.Position{})
		must(e)
		must(os.WriteFile(filepath.Join(d, "position.json"), raw, 0600))
		for i, name := range []string{"first", "conflict", "next"} {
			q := wire.Request{Kind: wire.Fence, Subject: p, Namespace: types.DomainHash("OMESH/guard-acceptance/scope", pub), Choice: types.DomainHash("OMESH/guard-acceptance/choice", []byte(name))}
			if i == 2 {
				q.Slot = 1
			}
			q, e = q.Sign(key)
			must(e)
			raw, e = q.CanonicalBytes()
			must(e)
			must(os.WriteFile(filepath.Join(d, name+".bin"), raw, 0600))
		}
	case "verify":
		if len(os.Args) != 5 {
			panic("verify needs identity request seal")
		}
		raw, e := os.ReadFile(os.Args[2])
		must(e)
		var id guard.Identity
		must(json.Unmarshal(raw, &id))
		raw, e = os.ReadFile(os.Args[3])
		must(e)
		q, e := wire.DecodeRequest(raw)
		must(e)
		raw, e = os.ReadFile(os.Args[4])
		must(e)
		if len(raw) != 64 {
			panic("seal length")
		}
		var seal [64]byte
		copy(seal[:], raw)
		must(q.VerifySeal(id.PublicKey, seal))
		fmt.Println("verified")
	default:
		panic("unknown action")
	}
}
