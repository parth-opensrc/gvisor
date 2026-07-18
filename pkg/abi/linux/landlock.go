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

// Matches Linux [include/uapi/linux/landlock.h]:landlock_ruleset_attr
//
// LandlockRulesetAttr represents struct landlock_ruleset_attr.
//
// +marshal
// +stateify savable
type LandlockRulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64
	Scoped           uint64
}

// Matches Linux [include/uapi/linux/landlock.h]:landlock_path_beneath_attr
//
// LandlockPathBeneathAttr represents struct landlock_path_beneath_attr.
//
// +marshal
// +stateify savable
type LandlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

// Matches Linux [include/uapi/linux/landlock.h]:landlock_create_ruleset_flags
const (
	LANDLOCK_CREATE_RULESET_VERSION = (1 << 0)
	LANDLOCK_CREATE_RULESET_ERRATA  = (1 << 1)
)

// Matches Linux [include/uapi/linux/landlock.h]:landlock_restrict_self_flags
const (
	LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF  = (1 << 0)
	LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON    = (1 << 1)
	LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF = (1 << 2)
)

// Matches Linux [include/uapi/linux/landlock.h]:landlock_rule_type
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// Matches Linux [include/uapi/linux/landlock.h]:fs_access
const (
	LANDLOCK_ACCESS_FS_EXECUTE     = (1 << 0)
	LANDLOCK_ACCESS_FS_WRITE_FILE  = (1 << 1)
	LANDLOCK_ACCESS_FS_READ_FILE   = (1 << 2)
	LANDLOCK_ACCESS_FS_READ_DIR    = (1 << 3)
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = (1 << 4)
	LANDLOCK_ACCESS_FS_REMOVE_FILE = (1 << 5)
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = (1 << 6)
	LANDLOCK_ACCESS_FS_MAKE_DIR    = (1 << 7)
	LANDLOCK_ACCESS_FS_MAKE_REG    = (1 << 8)
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = (1 << 9)
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = (1 << 10)
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = (1 << 11)
	LANDLOCK_ACCESS_FS_MAKE_SYM    = (1 << 12)
	LANDLOCK_ACCESS_FS_REFER       = (1 << 13)
	LANDLOCK_ACCESS_FS_TRUNCATE    = (1 << 14)
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = (1 << 15)
)

// LANDLOCK_MASK_ACCESS_FS_V1 defines the bitmask of handled filesystem access rights for ABI v1.
// Matches Linux [include/uapi/linux/landlock.h] (bits 0..12).
const LANDLOCK_MASK_ACCESS_FS_V1 = (1 << 13) - 1

// LANDLOCK_ACCESS_FS_FILE defines the access rights applicable to non-directory files.
// Matches Linux [security/landlock/fs.c]:landlock_append_fs_rule()
const LANDLOCK_ACCESS_FS_FILE = LANDLOCK_ACCESS_FS_EXECUTE |
	LANDLOCK_ACCESS_FS_WRITE_FILE |
	LANDLOCK_ACCESS_FS_READ_FILE |
	LANDLOCK_ACCESS_FS_TRUNCATE |
	LANDLOCK_ACCESS_FS_IOCTL_DEV

// Maximum layers and rules limits.
// Matches Linux [security/landlock/limits.h]
const (
	LANDLOCK_MAX_NUM_LAYERS = 16
	LANDLOCK_MAX_NUM_RULES  = 65535
)
