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

package garbage

import (
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func currentGCPercent() int {
	p := debug.SetGCPercent(-1 /* percent */)
	debug.SetGCPercent(p)
	return p
}

func currentMemoryLimit() int64 {
	return debug.SetMemoryLimit(-1 /* limit */)
}

func resetRuntimeGCSettings(t *testing.T, gcPercent int, memLimit int64) {
	t.Helper()
	runtime.GC()
	prevP := debug.SetGCPercent(gcPercent)
	prevL := debug.SetMemoryLimit(memLimit)
	t.Cleanup(func() {
		debug.SetGCPercent(prevP)
		debug.SetMemoryLimit(prevL)
	})
}

func TestSuspendAndEnd(t *testing.T) {
	const (
		origPercent = 125
		origLimit   = int64(2 << 30)
		totalMem    = 1 << 30
		wantLimit   = totalMem / 2
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)

	var nilSuspension *Suspension
	nilSuspension.End()
	(&Suspension{}).End()

	s := Suspend(totalMem, 0 /* untrackedMem */)
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent while suspended = %d, want -1", got)
	}
	if got := currentMemoryLimit(); got != wantLimit {
		t.Fatalf("MemoryLimit while suspended = %d, want %d", got, wantLimit)
	}

	// Allocating unreachable slices well below suspLimit must not trigger
	// periodic GC while GCPercent is -1.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 32 {
		buf := make([]byte, 512<<10)
		runtime.KeepAlive(buf)
	}
	runtime.ReadMemStats(&after)
	if after.NumGC != before.NumGC {
		t.Fatalf("NumGC changed during suspension: before=%d after=%d", before.NumGC, after.NumGC)
	}

	s.End()
	// Idempotent second call must be a no-op.
	s.End()

	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent after End = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after End = %d, want %d", got, origLimit)
	}
}

func TestNestedSuspensionsComposeLimits(t *testing.T) {
	const (
		origPercent  = 100
		origLimit    = int64(800 << 20)
		totalMemLow  = 512 << 20
		totalMemHigh = 1200 << 20
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)

	// An unlimited suspension (maxMemoryLimit = 1 GiB) exceeding the
	// pre-suspension limit is capped at origLimit.
	s1 := Suspend(NoMemoryLimit, 0 /* untrackedMem */)
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after s1 = %d, want %d", got, origLimit)
	}

	// A tighter nested suspension lowers the active limit.
	s2 := Suspend(totalMemHigh, 0 /* untrackedMem */)
	if got, want := currentMemoryLimit(), int64(totalMemHigh/2); got != want {
		t.Fatalf("MemoryLimit after s2 = %d, want %d", got, want)
	}

	// A looser nested suspension does not raise the active limit.
	s3 := Suspend(NoMemoryLimit, 0 /* untrackedMem */)
	if got, want := currentMemoryLimit(), int64(totalMemHigh/2); got != want {
		t.Fatalf("MemoryLimit after s3 = %d, want %d", got, want)
	}

	// An even tighter nested suspension lowers the active limit further.
	s4 := Suspend(totalMemLow, 0 /* untrackedMem */)
	if got, want := currentMemoryLimit(), int64(totalMemLow/2); got != want {
		t.Fatalf("MemoryLimit after s4 = %d, want %d", got, want)
	}

	s4.End()
	s3.End()
	s2.End()
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent with s1 still active = %d, want -1", got)
	}

	s1.End()
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent after all ended = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after all ended = %d, want %d", got, origLimit)
	}

	// An overlapping suspension with no remaining headroom resumes GC on the
	// active session immediately instead of leaving GC suspended.
	sOuter := Suspend(totalMemHigh, 0 /* untrackedMem */)
	defer sOuter.End()
	if sZero := Suspend(100<<20, 100<<20); sZero != nil {
		sZero.End()
		t.Fatalf("Suspend with exhausted budget while suspended = %v, want nil", sZero)
	}
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent after zero-headroom nested Suspend = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after zero-headroom nested Suspend = %d, want %d", got, origLimit)
	}
}

func TestEarlyResumeOnCollection(t *testing.T) {
	const (
		origPercent = 100
		origLimit   = int64(2 << 30)
		totalMem    = 1 << 30
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)

	s1 := Suspend(totalMem, 0 /* untrackedMem */)
	// Simulate the runtime forcing a GC cycle when memoryLimit is reached.
	runtime.GC()

	deadline := time.Now().Add(5 * time.Second)
	for currentGCPercent() == -1 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent after forced GC = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after forced GC = %d, want %d", got, origLimit)
	}

	// Further suspensions while resumed early have no effect until all active
	// handles have ended.
	s2 := Suspend(totalMem/2, 0 /* untrackedMem */)
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent on nested Suspend while resumed early = %d, want %d", got, origPercent)
	}
	s2.End()
	s1.End()

	// Once all handles from the resumed early suspension have ended, a new
	// suspension suspends GC normally again.
	s3 := Suspend(totalMem, 0 /* untrackedMem */)
	defer s3.End()
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent on fresh Suspend after resumed early suspension = %d, want -1", got)
	}
}

func TestFreeOSMemory(t *testing.T) {
	const (
		origPercent = 100
		origLimit   = int64(2 << 30)
		totalMem    = 1 << 30
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)

	s := Suspend(totalMem, 0 /* untrackedMem */)

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// FreeOSMemory while a suspension is active must not force a GC.
	FreeOSMemory()
	var mid runtime.MemStats
	runtime.ReadMemStats(&mid)
	if mid.NumGC != before.NumGC {
		t.Fatalf("FreeOSMemory forced GC while suspended: before=%d mid=%d", before.NumGC, mid.NumGC)
	}
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent with s active = %d, want -1", got)
	}

	// Even if a forced GC marks the active suspension resumed early while s is still
	// held (e.g., an active save/restore hit its soft limit), FreeOSMemory must
	// still not run another synchronous GC/scavenge until s.End() is called.
	runtime.GC()
	deadline := time.Now().Add(5 * time.Second)
	for currentGCPercent() == -1 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	var afterForced runtime.MemStats
	runtime.ReadMemStats(&afterForced)
	FreeOSMemory()
	var afterSkipped runtime.MemStats
	runtime.ReadMemStats(&afterSkipped)
	if afterSkipped.NumGC != afterForced.NumGC {
		t.Fatalf("FreeOSMemory forced GC while resumed early handle still active: before=%d after=%d", afterForced.NumGC, afterSkipped.NumGC)
	}

	// Once all active suspensions have ended, FreeOSMemory runs GC and
	// preserves previous settings without marking a subsequent suspension as
	// resumed early.
	s.End()
	FreeOSMemory()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.NumGC <= afterSkipped.NumGC {
		t.Fatalf("FreeOSMemory after End did not run GC: before=%d after=%d", afterSkipped.NumGC, after.NumGC)
	}
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent after FreeOSMemory = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit after FreeOSMemory = %d, want %d", got, origLimit)
	}

	// Ensure the intentional GC inside FreeOSMemory did not poison a subsequent
	// suspension via a stale sentinel cleanup.
	s2 := Suspend(totalMem, 0 /* untrackedMem */)
	defer s2.End()
	time.Sleep(5 * time.Millisecond)
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent on subsequent Suspend = %d, want -1", got)
	}
}

func TestDisableSuspend(t *testing.T) {
	const (
		origPercent = 100
		origLimit   = int64(2 << 30)
		totalMem    = 1 << 30
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)
	resetDisabled := func() {
		mu.Lock()
		suspendNoop = false
		mu.Unlock()
	}
	t.Cleanup(resetDisabled)

	DisableSuspend()
	sDisabled := Suspend(totalMem, 0 /* untrackedMem */)
	if sDisabled != nil {
		sDisabled.End()
		t.Fatalf("Suspend while disabled = %v, want nil", sDisabled)
	}
	if got := currentGCPercent(); got != origPercent {
		t.Fatalf("GCPercent while disabled = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		t.Fatalf("MemoryLimit while disabled = %d, want %d", got, origLimit)
	}
	sDisabled.End()

	// FreeOSMemory remains active when suspension is disabled.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	FreeOSMemory()
	runtime.ReadMemStats(&after)
	if after.NumGC <= before.NumGC {
		t.Fatalf("FreeOSMemory while disabled did not run GC: before=%d after=%d", before.NumGC, after.NumGC)
	}

	// Disabling mid-suspension restores settings immediately.
	resetDisabled()
	s1 := Suspend(totalMem, 0 /* untrackedMem */)
	if got := currentGCPercent(); got != -1 {
		s1.End()
		t.Fatalf("GCPercent after reset = %d, want -1", got)
	}

	DisableSuspend()
	if got := currentGCPercent(); got != origPercent {
		s1.End()
		t.Fatalf("GCPercent after DisableSuspend mid-suspension = %d, want %d", got, origPercent)
	}
	if got := currentMemoryLimit(); got != origLimit {
		s1.End()
		t.Fatalf("MemoryLimit after DisableSuspend mid-suspension = %d, want %d", got, origLimit)
	}
	s2 := Suspend(totalMem/2, 0 /* untrackedMem */)
	s2.End()
	s1.End()

	resetDisabled()
	s3 := Suspend(totalMem, 0 /* untrackedMem */)
	defer s3.End()
	if got := currentGCPercent(); got != -1 {
		t.Fatalf("GCPercent after reset following mid-suspension disable = %d, want -1", got)
	}
}

func TestSuspendAlreadyPastLimit(t *testing.T) {
	const (
		origPercent = 100
		origLimit   = int64(2 << 30)
	)
	resetRuntimeGCSettings(t, origPercent, origLimit)

	used, ok := memoryUsed()
	if !ok || used == 0 {
		t.Fatalf("memoryUsed() = (%d, %v), want (>0, true)", used, ok)
	}

	for _, totalMem := range []uint64{0, 1, 2, 2 * used, 4 * used} {
		if s := Suspend(totalMem, 0 /* untrackedMem */); s != nil {
			s.End()
			t.Fatalf("Suspend(%d, 0) with memoryUsed()=%d = %v, want nil", totalMem, used, s)
		}
		if got := currentGCPercent(); got != origPercent {
			t.Fatalf("GCPercent after Suspend(%d, 0) = %d, want %d", totalMem, got, origPercent)
		}
		if got := currentMemoryLimit(); got != origLimit {
			t.Fatalf("MemoryLimit after Suspend(%d, 0) = %d, want %d", totalMem, got, origLimit)
		}
	}

	// Exhausted untrackedMem budget skips suspension.
	if s := Suspend(100<<20, 100<<20); s != nil {
		s.End()
		t.Fatalf("Suspend with exhausted budget = %v, want nil", s)
	}

	// If less than half of a pre-existing GOMEMLIMIT remains free (or it is 0),
	// Suspend skips disabling GC even when totalMem is unlimited.
	for _, preLimit := range []int64{0, int64(used), int64(2 * used)} {
		debug.SetMemoryLimit(preLimit)
		if s := Suspend(NoMemoryLimit, 0 /* untrackedMem */); s != nil {
			s.End()
			t.Fatalf("Suspend with pre-existing limit %d and used=%d = %v, want nil", preLimit, used, s)
		}
		if got := currentGCPercent(); got != origPercent {
			t.Fatalf("GCPercent with pre-existing limit %d = %d, want %d", preLimit, got, origPercent)
		}
	}
}

func TestMemoryLimit(t *testing.T) {
	tcs := []struct {
		name         string
		totalMem     uint64
		untrackedMem uint64
		want         uint64
	}{
		{
			name:     "noMemoryLimitUsesMax",
			totalMem: NoMemoryLimit,
			want:     maxMemoryLimit,
		},
		{
			name:         "noMemoryLimitWithUntrackedUsesMax",
			totalMem:     NoMemoryLimit,
			untrackedMem: 512 << 20,
			want:         maxMemoryLimit,
		},
		{
			name:         "largeCgroupCappedAtMax",
			totalMem:     4 << 30,
			untrackedMem: 512 << 20,
			want:         maxMemoryLimit,
		},
		{
			name:     "mediumCgroupScalesToHalf",
			totalMem: 1 << 30,
			want:     512 << 20,
		},
		{
			name:     "tightCgroupCapsToHalf",
			totalMem: 200 << 20,
			want:     100 << 20,
		},
		{
			name:         "untrackedMemReducesRemainingBudget",
			totalMem:     200 << 20,
			untrackedMem: 140 << 20,
			want:         30 << 20,
		},
		{
			name:         "untrackedMemExceedingTotalMemReturnsZero",
			totalMem:     100 << 20,
			untrackedMem: 120 << 20,
			want:         0,
		},
		{
			name:     "zeroTotalMemReturnsZero",
			totalMem: 0,
			want:     0,
		},
		{
			name:     "oneByteTotalMemReturnsZero",
			totalMem: 1,
			want:     0,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := memoryLimit(tc.totalMem, tc.untrackedMem); got != tc.want {
				t.Fatalf("memoryLimit(%d, %d) = %d, want %d", tc.totalMem, tc.untrackedMem, got, tc.want)
			}
		})
	}
}
