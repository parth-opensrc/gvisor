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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
//
// LandlockCreateRuleset implements landlock_create_ruleset(2).
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return 1, nil, nil // Return Landlock ABI version 1
		}
		return 0, nil, linuxerr.EINVAL
	}

	if size < 8 { // Must be at least sizeof(handled_access_fs)
		return 0, nil, linuxerr.EINVAL
	}
	if size > 4096 { // Matches Linux [security/landlock/syscalls.c]:copy_min_struct_from_user() PAGE_SIZE check
		return 0, nil, linuxerr.E2BIG
	}

	var attr linux.LandlockRulesetAttr
	bytesToCopy := size
	if bytesToCopy > 24 { // sizeof(linux.LandlockRulesetAttr)
		bytesToCopy = 24
	}
	buf := make([]byte, 24)
	if _, err := t.CopyInBytes(attrAddr, buf[:bytesToCopy]); err != nil {
		return 0, nil, err
	}
	attr.UnmarshalBytes(buf)

	// Matches Linux [security/landlock/syscalls.c]:copy_min_struct_from_user() trailing zero check
	if size > 24 {
		extraBuf := make([]byte, size-24)
		if _, err := t.CopyInBytes(attrAddr+24, extraBuf); err != nil {
			return 0, nil, err
		}
		for _, b := range extraBuf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	if attr.HandledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if attr.HandledAccessFS&^uint64(linux.LANDLOCK_MASK_ACCESS_FS_V1) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if attr.HandledAccessNet != 0 || attr.Scoped != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ruleset := auth.NewLandlockRuleset(attr.HandledAccessFS)
	vfsFD, err := t.Kernel().VFS().NewLandlockRulesetFD(t, ruleset)
	if err != nil {
		return 0, nil, err
	}
	defer vfsFD.DecRef(t)

	fd, err := t.NewFDFrom(0, vfsFD, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// Matches Linux [security/landlock/syscalls.c]:sys_landlock_add_rule()
//
// LandlockAddRule implements landlock_add_rule(2).
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	ruleType := args[1].Uint()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFile(rulesetFD)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
	rulesetFDImpl, ok := file.Impl().(*vfs.LandlockRulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}
	ruleset := rulesetFDImpl.Ruleset()

	var attr linux.LandlockPathBeneathAttr
	if _, err := attr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, err
	}

	// Matches Linux [security/landlock/syscalls.c]:add_rule_path_beneath()
	if attr.AllowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if attr.AllowedAccess&^ruleset.HandledAccessFS != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd()
	parentFile := t.GetFile(attr.ParentFD)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	if _, isRulesetFD := parentFile.Impl().(*vfs.LandlockRulesetFD); isRulesetFD {
		return 0, nil, linuxerr.EBADFD
	}

	vd := parentFile.VirtualDentry()
	dentry := vd.Dentry()
	if dentry == nil {
		return 0, nil, linuxerr.EBADF
	}

	stat, err := parentFile.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		return 0, nil, err
	}
	isDir := stat.Mode&linux.S_IFMT == linux.S_IFDIR

	// File access rights restriction:
	// Matches Linux [security/landlock/fs.c]:landlock_append_fs_rule()
	if !isDir && (attr.AllowedAccess&^uint64(linux.LANDLOCK_ACCESS_FS_FILE)) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ruleset.AddPathRule(dentry, attr.AllowedAccess)
	return 0, nil, nil
}

// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
//
// LandlockRestrictSelf implements landlock_restrict_self(2).
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
	// Security Hazard 1: Check NoNewPrivs or CAP_SYS_ADMIN.
	if !t.GetNoNewPrivs() && !t.HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	file := t.GetFile(rulesetFD)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	rulesetFDImpl, ok := file.Impl().(*vfs.LandlockRulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}
	ruleset := rulesetFDImpl.Ruleset()

	creds := t.Credentials()
	newDomain, err := creds.LandlockDomain.Merge(ruleset)
	if err != nil {
		return 0, nil, err
	}

	newCreds := creds.Fork()
	newCreds.LandlockDomain = newDomain
	t.SetCredentials(newCreds)

	return 0, nil, nil
}
