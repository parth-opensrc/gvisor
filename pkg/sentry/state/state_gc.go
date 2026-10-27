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
	"strconv"

	"gvisor.dev/gvisor/pkg/garbage"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// metadataMemoryFileUsedBytesKey is the save metadata key for pre-save
// MemoryFile byte usage.
const metadataMemoryFileUsedBytesKey = "gvisor_memory_file_used_bytes"

// totalMemoryLimit maps usage.MaximumTotalMemoryBytes (0 if unlimited) to a
// garbage.Suspend limit.
func totalMemoryLimit() uint64 {
	if usage.MaximumTotalMemoryBytes == 0 {
		return garbage.NoMemoryLimit
	}
	return usage.MaximumTotalMemoryBytes
}

// suspendGCForSave suspends GC for a checkpoint save.
func suspendGCForSave(memoryFileBytes uint64) *garbage.Suspension {
	return garbage.Suspend(totalMemoryLimit(), memoryFileBytes)
}

// SuspendGCForRestore suspends GC for a checkpoint restore.
func SuspendGCForRestore(metadata map[string]string) *garbage.Suspension {
	var savedMemoryFileBytes uint64
	if v, err := strconv.ParseUint(metadata[metadataMemoryFileUsedBytesKey], 10 /* base */, 64 /* bitSize */); err == nil {
		savedMemoryFileBytes = v
	}
	return garbage.Suspend(totalMemoryLimit(), savedMemoryFileBytes)
}
