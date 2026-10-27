// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sentrycmd

import (
	"runtime/debug"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

func TestSuspendGCForBoot(t *testing.T) {
	origGOGC := debug.SetGCPercent(100)
	origLimit := debug.SetMemoryLimit(-1)
	defer func() {
		debug.SetGCPercent(origGOGC)
		debug.SetMemoryLimit(origLimit)
	}()

	conf := &config.Config{SuspendLifecycleGC: config.SuspendLifecycleGCAll}

	// Unlimited totalMem (0) caps the soft memory limit at 1 GiB.
	s := suspendGCForBoot(conf, 0)
	if s == nil {
		t.Fatal("suspendGCForBoot(0) = nil, want non-nil")
	}
	if got, want := debug.SetMemoryLimit(-1), int64(1<<30); got != want {
		t.Fatalf("memory limit = %d, want %d", got, want)
	}
	debug.SetMemoryLimit(1 << 30)
	s.End()

	// Explicit totalMem uses half of totalMem.
	s = suspendGCForBoot(conf, 400<<20)
	if s == nil {
		t.Fatal("suspendGCForBoot(400 MiB) = nil, want non-nil")
	}
	if got, want := debug.SetMemoryLimit(-1), int64(200<<20); got != want {
		t.Fatalf("memory limit = %d, want %d", got, want)
	}
	debug.SetMemoryLimit(200 << 20)
	s.End()

	// SuspendLifecycleGCNone permanently disables suspension for the process.
	noneConf := &config.Config{SuspendLifecycleGC: config.SuspendLifecycleGCNone}
	if s := suspendGCForBoot(noneConf, 400<<20); s != nil {
		s.End()
		t.Fatal("suspendGCForBoot(SuspendLifecycleGCNone) != nil, want nil")
	}
	if s := suspendGCForBoot(conf, 400<<20); s != nil {
		s.End()
		t.Fatal("suspendGCForBoot after DisableSuspend != nil, want nil")
	}
}
