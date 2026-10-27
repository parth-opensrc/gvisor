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

package state

import (
	"math"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func TestSuspendGCForSaveAndRestore(t *testing.T) {
	runtime.GC()
	prevP := debug.SetGCPercent(100 /* percent */)
	prevL := debug.SetMemoryLimit(math.MaxInt64)
	prevMaxMem := usage.MaximumTotalMemoryBytes
	usage.MaximumTotalMemoryBytes = 0
	t.Cleanup(func() {
		usage.MaximumTotalMemoryBytes = prevMaxMem
		debug.SetGCPercent(prevP)
		debug.SetMemoryLimit(prevL)
	})

	const defaultLimit = int64(1 << 30)
	sSave := suspendGCForSave(0 /* memoryFileBytes */)
	if got := debug.SetMemoryLimit(-1 /* limit */); got != defaultLimit {
		sSave.End()
		t.Fatalf("MemoryLimit during save = %d, want %d", got, defaultLimit)
	}
	sSave.End()

	tcs := []struct {
		name     string
		totalMem uint64
		metadata map[string]string
		want     int64
	}{
		{
			name:     "nilMetadata",
			metadata: nil,
			want:     defaultLimit,
		},
		{
			name:     "malformedMetadata",
			metadata: map[string]string{metadataMemoryFileUsedBytesKey: "not-a-number"},
			want:     defaultLimit,
		},
		{
			name:     "overflowMetadataIgnored",
			metadata: map[string]string{metadataMemoryFileUsedBytesKey: "99999999999999999999999999"},
			totalMem: 200 << 20,
			want:     100 << 20,
		},
		{
			name:     "largeCgroupCappedAtMax",
			totalMem: 4 << 30,
			want:     defaultLimit,
		},
		{
			name:     "mediumCgroupScalesLimit",
			totalMem: 1 << 30,
			want:     512 << 20,
		},
		{
			name:     "cgroupCapsRestoreLimit",
			totalMem: 200 << 20,
			want:     100 << 20,
		},
		{
			name:     "cgroupAndMemoryFileCapRestoreLimit",
			totalMem: 200 << 20,
			metadata: map[string]string{
				metadataMemoryFileUsedBytesKey: strconv.FormatUint(80<<20, 10 /* base */),
			},
			want: 60 << 20,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			usage.MaximumTotalMemoryBytes = tc.totalMem
			s := SuspendGCForRestore(tc.metadata)
			defer s.End()
			if got := debug.SetMemoryLimit(-1 /* limit */); got != tc.want {
				t.Fatalf("MemoryLimit during restore = %d, want %d", got, tc.want)
			}
		})
	}

	// When non-Go memory already exhausts the cgroup budget, suspension is
	// skipped so normal GC remains active.
	usage.MaximumTotalMemoryBytes = 64 << 20
	if s := SuspendGCForRestore(map[string]string{
		metadataMemoryFileUsedBytesKey: strconv.FormatUint(64<<20, 10 /* base */),
	}); s != nil {
		s.End()
		t.Fatalf("SuspendGCForRestore with exhausted cgroup budget = %v, want nil", s)
	}
}
