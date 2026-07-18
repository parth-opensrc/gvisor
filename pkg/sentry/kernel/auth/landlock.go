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

package auth

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// Matches Linux [security/landlock/ruleset.h]:landlock_rule
//
// LandlockPathRule represents a rule targeting a directory or file hierarchy.
type LandlockPathRule struct {
	TargetKey     any // Holds *vfs.Dentry (kept opaque to avoid import cycle with vfs)
	AllowedAccess uint64
}

// Matches Linux [security/landlock/ruleset.h]:landlock_ruleset
//
// LandlockRuleset represents an un-enforced Landlock ruleset created by sys_landlock_create_ruleset.
type LandlockRuleset struct {
	mu              sync.Mutex
	HandledAccessFS uint64
	Rules           []LandlockPathRule
}

// NewLandlockRuleset creates a new un-enforced Landlock ruleset.
// Matches Linux [security/landlock/ruleset.c]:landlock_create_ruleset()
func NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	return &LandlockRuleset{
		HandledAccessFS: handledAccessFS,
	}
}

// AddPathRule adds a path beneath rule to the ruleset.
// Matches Linux [security/landlock/ruleset.c]:landlock_insert_rule()
func (r *LandlockRuleset) AddPathRule(targetKey any, allowedAccess uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Rules = append(r.Rules, LandlockPathRule{
		TargetKey:     targetKey,
		AllowedAccess: allowedAccess,
	})
}

// Matches Linux [security/landlock/ruleset.h]:landlock_layer
//
// LandlockLayer represents a single policy layer in a Landlock domain stack.
type LandlockLayer struct {
	HandledAccessFS uint64
	Rules           []LandlockPathRule
}

// Matches Linux [security/landlock/domain.h]:landlock_hierarchy
//
// LandlockDomain represents an immutable stacked Landlock security domain.
type LandlockDomain struct {
	Layers []LandlockLayer
}

// Merge creates a new LandlockDomain by appending ruleset as a new layer on top of parent domain.
// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
func (parent *LandlockDomain) Merge(ruleset *LandlockRuleset) (*LandlockDomain, error) {
	ruleset.mu.Lock()
	defer ruleset.mu.Unlock()

	numLayers := 1
	if parent != nil {
		numLayers = len(parent.Layers) + 1
	}
	if numLayers > linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	newLayers := make([]LandlockLayer, 0, numLayers)
	if parent != nil {
		newLayers = append(newLayers, parent.Layers...)
	}

	rulesCopy := make([]LandlockPathRule, len(ruleset.Rules))
	copy(rulesCopy, ruleset.Rules)

	newLayers = append(newLayers, LandlockLayer{
		HandledAccessFS: ruleset.HandledAccessFS,
		Rules:           rulesCopy,
	})

	return &LandlockDomain{
		Layers: newLayers,
	}, nil
}
