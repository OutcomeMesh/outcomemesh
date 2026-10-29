//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRadixMigrationCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_TEST_RADIX_CRASH")
	if stage == "" {
		return
	}
	var args []string
	if e := json.Unmarshal([]byte(os.Getenv("OUTCOMEMESH_TEST_RADIX_ARGS")), &args); e != nil {
		t.Fatal(e)
	}
	e := workMigrateRadix(context.Background(), args, os.Stdout, func(at string) error {
		if at != stage {
			return nil
		}
		fmt.Println("migration-paused")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return errors.New("crash barrier input closed")
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestProcessWorkRadixMigrationCrashAndColdPublication(t *testing.T) {
	src := migrationFixture(t)
	original := migrationDigest(t, src)
	for _, stage := range []string{"prepared", "block", "before-publish", "published"} {
		t.Run(stage, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "partial")
			args, pin := migrationReview(t, src, dst, 5)
			args = append(args, "--mode", "run", "--expected-review-id", pin)
			raw, _ := json.Marshal(args)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRadixMigrationCrashHelper$")
			child.Env = append(os.Environ(), "OUTCOMEMESH_TEST_RADIX_CRASH="+stage, "OUTCOMEMESH_TEST_RADIX_ARGS="+string(raw))
			stdin, e := child.StdinPipe()
			if e != nil {
				t.Fatal(e)
			}
			defer stdin.Close()
			stdout, e := child.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			defer stdout.Close()
			var stderr bytes.Buffer
			child.Stderr = &stderr
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if child.ProcessState == nil {
					child.Process.Kill()
					child.Wait()
				}
			}()
			ready := make(chan bool, 1)
			go func() {
				scan := bufio.NewScanner(stdout)
				for scan.Scan() {
					if scan.Text() == "migration-paused" {
						ready <- true
						return
					}
				}
				ready <- false
			}()
			select {
			case ok := <-ready:
				if !ok {
					child.Wait()
					t.Fatal("child barrier", stderr.String())
				}
			case <-ctx.Done():
				child.Wait()
				t.Fatal("barrier deadline", stderr.String())
			}
			other := filepath.Join(t.TempDir(), "blocked")
			if _, e = runProcessCommandError(10*time.Second, "work-migrate-radix", "--source", src, "--out", other, "--radix-height", "5"); e == nil {
				t.Fatal("another process entered locked source")
			}
			if e = child.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e = child.Wait(); e == nil {
				t.Fatal("child survived kill")
			}
			if stage == "published" {
				if _, e = os.Stat(filepath.Join(dst, workActivationPending)); !os.IsNotExist(e) {
					t.Fatal("pending after publication", e)
				}
				if _, e = os.Stat(filepath.Join(dst, workActivationFilename)); e != nil {
					t.Fatal("lost publication", e)
				}
				runProcessCommand(t, 20*time.Second, "work-verify", "--data", dst)
			} else {
				if _, e = os.Stat(filepath.Join(dst, workActivationPending)); e != nil {
					t.Fatal("lost pending marker", e)
				}
				if _, e = os.Stat(filepath.Join(dst, workActivationFilename)); !os.IsNotExist(e) {
					t.Fatal("partial publication", e)
				}
			}
			if !reflect.DeepEqual(original, migrationDigest(t, src)) {
				t.Fatal("killed migration changed source")
			}
		})
	}
	dst := filepath.Join(t.TempDir(), "complete")
	review := runProcessCommand(t, 20*time.Second, "work-migrate-radix", "--source", src, "--out", dst, "--radix-height", "5")
	pin := strings.Split(strings.Split(review, "review_id=")[1], "\n")[0]
	runProcessCommand(t, 20*time.Second, "work-migrate-radix", "--source", src, "--out", dst, "--radix-height", "5", "--mode", "run", "--expected-review-id", pin)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", dst, "--count", "3")
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dst)
	status := outputFields(runProcessCommand(t, 20*time.Second, "work-status", "--data", dst), "work_status")
	if status["height"] != "6" || status["radix_height"] != "5" || status["commitment"] != "1" {
		t.Fatal("cold destination", status)
	}
	if !reflect.DeepEqual(original, migrationDigest(t, src)) {
		t.Fatal("cold publication changed source")
	}
}
