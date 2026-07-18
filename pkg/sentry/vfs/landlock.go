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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Matches Linux [security/landlock/syscalls.c]:ruleset_fops
//
// LandlockRulesetFD implements FileDescriptionImpl for [landlock-ruleset] anonymous FDs.
type LandlockRulesetFD struct {
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	vfsfd   FileDescription
	ruleset *auth.LandlockRuleset
}

// NewLandlockRulesetFD returns a FileDescription representing a Landlock ruleset.
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func (vfs *VirtualFilesystem) NewLandlockRulesetFD(ctx context.Context, ruleset *auth.LandlockRuleset) (*FileDescription, error) {
	vd := vfs.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	fd := &LandlockRulesetFD{
		ruleset: ruleset,
	}
	if err := fd.vfsfd.Init(fd, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Ruleset returns the underlying LandlockRuleset.
func (fd *LandlockRulesetFD) Ruleset() *auth.LandlockRuleset {
	return fd.ruleset
}

// Release implements FileDescriptionImpl.Release.
func (fd *LandlockRulesetFD) Release(ctx context.Context) {}

// CheckLandlockAccess checks if requestedAccess on vd is permitted by creds.LandlockDomain.
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (vfs *VirtualFilesystem) CheckLandlockAccess(ctx context.Context, creds *auth.Credentials, vd VirtualDentry, requestedAccess uint64) error {
	if creds == nil || creds.LandlockDomain == nil || requestedAccess == 0 {
		return nil
	}

	domain := creds.LandlockDomain
	for _, layer := range domain.Layers {
		remaining := requestedAccess & layer.HandledAccessFS
		if remaining == 0 {
			continue
		}

		currVD := vd
		for currVD.Ok() {
			for _, rule := range layer.Rules {
				ruleDentry, ok := rule.TargetKey.(*Dentry)
				if !ok || ruleDentry == nil {
					continue
				}

				if currVD.mount != nil && currVD.mount.fs != nil && currVD.mount.fs.impl != nil {
					ruleVD := VirtualDentry{mount: currVD.mount, dentry: ruleDentry}
					if currVD.mount.fs.impl.IsDescendant(ruleVD, currVD) {
						remaining &= ^rule.AllowedAccess
						if remaining == 0 {
							break
						}
					}
				}
			}

			if remaining == 0 {
				if currVD != vd {
					currVD.DecRef(ctx)
				}
				break
			}

			nextVD := vfs.getMountpointAt(ctx, currVD.mount, VirtualDentry{})
			if currVD != vd {
				currVD.DecRef(ctx)
			}
			if !nextVD.Ok() || nextVD == currVD {
				if nextVD.Ok() {
					nextVD.DecRef(ctx)
				}
				break
			}
			currVD = nextVD
		}

		if remaining != 0 {
			return linuxerr.EACCES
		}
	}

	return nil
}
