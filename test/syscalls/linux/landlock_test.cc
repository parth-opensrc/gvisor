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

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

enum landlock_rule_type {
  LANDLOCK_RULE_PATH_BENEATH = 1,
};

struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
};

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

namespace gvisor {
namespace testing {

namespace {

inline int landlock_create_ruleset(const struct landlock_ruleset_attr* attr,
                                   size_t size, uint32_t flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
                             const void* rule_attr, uint32_t flags) {
  return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                 flags);
}

inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

TEST(LandlockTest, VersionQuery) {
  // LANDLOCK_CREATE_RULESET_VERSION must return >= 1 (ABI version) when attr is
  // NULL and size is 0.
  int version =
      landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  ASSERT_THAT(version, SyscallSucceeds());
  EXPECT_GE(version, 1);

  // If attr is non-NULL or size is non-zero with
  // LANDLOCK_CREATE_RULESET_VERSION, return EINVAL.
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_VERSION),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, CreateRulesetValidation) {
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

  // Invalid flags -> EINVAL.
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 1U << 31),
              SyscallFailsWithErrno(EINVAL));

  // Zero handled_access_fs -> ENOMSG.
  struct landlock_ruleset_attr empty_attr = {};
  empty_attr.handled_access_fs = 0;
  EXPECT_THAT(landlock_create_ruleset(&empty_attr, sizeof(empty_attr), 0),
              SyscallFailsWithErrno(ENOMSG));

  // Unsupported access bits (e.g. unknown bit 63) -> EINVAL.
  struct landlock_ruleset_attr invalid_attr = {};
  invalid_attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&invalid_attr, sizeof(invalid_attr), 0),
              SyscallFailsWithErrno(EINVAL));

  // Size > 4096 -> E2BIG.
  EXPECT_THAT(landlock_create_ruleset(&attr, 4097, 0),
              SyscallFailsWithErrno(E2BIG));

  // Valid creation.
  struct landlock_ruleset_attr valid_attr = {};
  valid_attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
  int ruleset_fd = landlock_create_ruleset(&valid_attr, sizeof(valid_attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  EXPECT_THAT(close(ruleset_fd), SyscallSucceeds());
}

TEST(LandlockTest, RestrictSelfPrivilegeCheck) {
  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    // Drop CAP_SYS_ADMIN if held.
    if (EXPECT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN))) {
      TEST_PCHECK(DropPermittedCapability(CAP_SYS_ADMIN).ok());
    }

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    // Without no_new_privs and without CAP_SYS_ADMIN, restrict_self
    // returns EPERM.
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == -1 && errno == EPERM);

    // Set no_new_privs.
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    // With no_new_privs, restrict_self succeeds.
    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);

    close(ruleset_fd);
    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, PathBeneathFileAccess) {
  auto allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto forbidden_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto allowed_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  auto forbidden_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(forbidden_dir.path()));

  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    int dir_fd = open(allowed_dir.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(dir_fd >= 0);

    struct landlock_path_beneath_attr path_attr = {};
    path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    path_attr.parent_fd = dir_fd;

    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr, 0) == 0);
    close(dir_fd);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Reading allowed_file succeeds.
    int fd = open(allowed_file.path().c_str(), O_RDONLY);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) close(fd);

    // Writing allowed_file fails with EACCES.
    fd = open(allowed_file.path().c_str(), O_WRONLY);
    TEST_CHECK(fd == -1 && errno == EACCES);

    // Reading forbidden_file fails with EACCES.
    fd = open(forbidden_file.path().c_str(), O_RDONLY);
    TEST_CHECK(fd == -1 && errno == EACCES);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, DirectoryModificationRights) {
  auto dir_test = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto other_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    int test_dir_fd = open(dir_test.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(test_dir_fd >= 0);

    struct landlock_path_beneath_attr path_attr = {};
    path_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_DIR;
    path_attr.parent_fd = test_dir_fd;

    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr, 0) == 0);
    close(test_dir_fd);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    std::string allowed_subdir = dir_test.path() + "/new_dir";
    std::string forbidden_subdir = other_dir.path() + "/new_dir";

    // Creating directory under dir_test succeeds.
    TEST_PCHECK(mkdir(allowed_subdir.c_str(), 0755) == 0);

    // Creating directory under other_dir fails with EACCES.
    TEST_CHECK(mkdir(forbidden_subdir.c_str(), 0755) == -1 && errno == EACCES);

    // Removing directory under dir_test fails with EACCES because REMOVE_DIR
    // was not granted.
    TEST_CHECK(rmdir(allowed_subdir.c_str()) == -1 && errno == EACCES);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, LinkRenameReparenting) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));

  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs =
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    int fd1 = open(dir1.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(fd1 >= 0);
    int fd2 = open(dir2.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(fd2 >= 0);

    struct landlock_path_beneath_attr path_attr1 = {};
    path_attr1.allowed_access = attr.handled_access_fs;
    path_attr1.parent_fd = fd1;
    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr1, 0) == 0);
    close(fd1);

    struct landlock_path_beneath_attr path_attr2 = {};
    path_attr2.allowed_access = attr.handled_access_fs;
    path_attr2.parent_fd = fd2;
    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr2, 0) == 0);
    close(fd2);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    std::string dst_file = dir2.path() + "/dst";
    // Under Landlock v1, reparenting links between different parent
    // directories returns EXDEV or EACCES.
    int ret = link(src_file.path().c_str(), dst_file.c_str());
    TEST_CHECK(ret == -1 && (errno == EXDEV || errno == EACCES));

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, DomainStackingLimit) {
  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

    // Apply up to 16 ruleset layers.
    for (int i = 0; i < 16; ++i) {
      int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
      TEST_PCHECK(ruleset_fd >= 0);
      TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
      close(ruleset_fd);
    }

    // 17th ruleset layer should fail with E2BIG.
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == -1 && errno == E2BIG);
    close(ruleset_fd);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, AddRuleValidation) {
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  Cleanup close_ruleset([ruleset_fd]() { close(ruleset_fd); });

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int dir_fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY);
  ASSERT_THAT(dir_fd, SyscallSucceeds());
  Cleanup close_dir([dir_fd]() { close(dir_fd); });

  struct landlock_path_beneath_attr path_attr = {};
  path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_attr.parent_fd = dir_fd;

  // Invalid ruleset_fd -> EBADF.
  EXPECT_THAT(landlock_add_rule(-1, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
              SyscallFailsWithErrno(EBADF));

  // Non-ruleset FD passed as ruleset_fd -> EBADFD.
  int dev_null_fd = open("/dev/null", O_RDONLY);
  ASSERT_THAT(dev_null_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(dev_null_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
      SyscallFailsWithErrno(EBADFD));
  close(dev_null_fd);

  // ruleset_fd passed as parent_fd -> EBADFD.
  struct landlock_path_beneath_attr ruleset_as_parent_attr = path_attr;
  ruleset_as_parent_attr.parent_fd = ruleset_fd;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &ruleset_as_parent_attr, 0),
              SyscallFailsWithErrno(EBADFD));

  // Invalid rule_type -> EINVAL.
  EXPECT_THAT(landlock_add_rule(ruleset_fd, static_cast<landlock_rule_type>(0),
                                &path_attr, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, static_cast<landlock_rule_type>(999),
                        &path_attr, 0),
      SyscallFailsWithErrno(EINVAL));

  // Non-zero flags -> EINVAL.
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 1),
      SyscallFailsWithErrno(EINVAL));

  // Null rule_attr -> EFAULT.
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, nullptr, 0),
      SyscallFailsWithErrno(EFAULT));

  // Invalid parent_fd inside struct -> EBADF.
  struct landlock_path_beneath_attr invalid_parent_attr = path_attr;
  invalid_parent_attr.parent_fd = -1;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &invalid_parent_attr, 0),
              SyscallFailsWithErrno(EBADF));

  // allowed_access = 0 -> ENOMSG.
  struct landlock_path_beneath_attr zero_access_attr = path_attr;
  zero_access_attr.allowed_access = 0;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &zero_access_attr, 0),
              SyscallFailsWithErrno(ENOMSG));

  // allowed_access asking for permissions not handled by ruleset -> EINVAL.
  struct landlock_path_beneath_attr unhandled_attr = path_attr;
  unhandled_attr.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &unhandled_attr, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, RestrictSelfValidation) {
  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    // Invalid ruleset_fd -> EBADF.
    TEST_CHECK(landlock_restrict_self(-1, 0) == -1 && errno == EBADF);

    // Non-ruleset FD passed as ruleset_fd -> EBADFD.
    int dev_null_fd = open("/dev/null", O_RDONLY);
    TEST_PCHECK(dev_null_fd >= 0);
    TEST_CHECK(landlock_restrict_self(dev_null_fd, 0) == -1 && errno == EBADFD);
    close(dev_null_fd);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    // Non-zero flags -> EINVAL.
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 1U << 31) == -1 &&
               errno == EINVAL);
    close(ruleset_fd);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, MountRestricted) {
  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Attempting mount after restrict_self returns EPERM regardless of
    // capabilities.
    TEST_CHECK(mount("none", "/tmp", "tmpfs", 0, nullptr) == -1 &&
               errno == EPERM);
    TEST_CHECK(umount2("/tmp", 0) == -1 && errno == EPERM);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, LayeredDomainEvaluation) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));

  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    // Layer 1: Handles READ and WRITE, grants both on dir1.
    struct landlock_ruleset_attr attr1 = {};
    attr1.handled_access_fs =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset1_fd = landlock_create_ruleset(&attr1, sizeof(attr1), 0);
    TEST_PCHECK(ruleset1_fd >= 0);

    int dir1_fd = open(dir1.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(dir1_fd >= 0);

    struct landlock_path_beneath_attr path_attr1 = {};
    path_attr1.allowed_access = attr1.handled_access_fs;
    path_attr1.parent_fd = dir1_fd;
    TEST_PCHECK(landlock_add_rule(ruleset1_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr1, 0) == 0);
    close(dir1_fd);

    TEST_PCHECK(landlock_restrict_self(ruleset1_fd, 0) == 0);
    close(ruleset1_fd);

    // Layer 2: Handles WRITE, grants WRITE on dir2 (not dir1).
    struct landlock_ruleset_attr attr2 = {};
    attr2.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset2_fd = landlock_create_ruleset(&attr2, sizeof(attr2), 0);
    TEST_PCHECK(ruleset2_fd >= 0);

    int dir2_fd = open(dir2.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(dir2_fd >= 0);

    struct landlock_path_beneath_attr path_attr2 = {};
    path_attr2.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
    path_attr2.parent_fd = dir2_fd;
    TEST_PCHECK(landlock_add_rule(ruleset2_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr2, 0) == 0);
    close(dir2_fd);

    TEST_PCHECK(landlock_restrict_self(ruleset2_fd, 0) == 0);
    close(ruleset2_fd);

    // Reading file1 in dir1: Layer 1 permits READ; Layer 2 does not handle
    // READ, so Layer 2 permits READ -> Read succeeds.
    int fd = open(file1.path().c_str(), O_RDONLY);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) close(fd);

    // Writing file1 in dir1: Layer 1 permits WRITE; Layer 2 handles WRITE but
    // does not grant it on dir1 -> Write fails with EACCES.
    fd = open(file1.path().c_str(), O_WRONLY);
    TEST_CHECK(fd == -1 && errno == EACCES);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, SiblingProcessInvariance) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  // Default state: main process can read and write file normally.
  int fd = open(file.path().c_str(), O_RDWR);
  ASSERT_THAT(fd, SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  pid_t restricted_child = fork();
  TEST_PCHECK(restricted_child >= 0);
  if (restricted_child == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Restricted child cannot write file.
    int child_fd = open(file.path().c_str(), O_WRONLY);
    TEST_CHECK(child_fd == -1 && errno == EACCES);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(restricted_child, &status, 0),
              SyscallSucceedsWithValue(restricted_child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Sibling / Parent process invariance: process remains unrestricted.
  fd = open(file.path().c_str(), O_RDWR);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) close(fd);
}

TEST(LandlockTest, NestedPathBeneathAccess) {
  auto parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string sub_dir_path = parent_dir.path() + "/sub/deep";
  ASSERT_THAT(mkdir((parent_dir.path() + "/sub").c_str(), 0755),
              SyscallSucceeds());
  ASSERT_THAT(mkdir(sub_dir_path.c_str(), 0755), SyscallSucceeds());
  auto deep_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sub_dir_path));

  pid_t child_pid = fork();
  TEST_PCHECK(child_pid >= 0);
  if (child_pid == 0) {
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_PCHECK(ruleset_fd >= 0);

    int dir_fd = open(parent_dir.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(dir_fd >= 0);

    struct landlock_path_beneath_attr path_attr = {};
    path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    path_attr.parent_fd = dir_fd;
    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_attr, 0) == 0);
    close(dir_fd);

    TEST_PCHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Reading nested file deep inside parent_dir succeeds.
    int fd = open(deep_file.path().c_str(), O_RDONLY);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) close(fd);

    // Writing nested file fails with EACCES.
    fd = open(deep_file.path().c_str(), O_WRONLY);
    TEST_CHECK(fd == -1 && errno == EACCES);

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Child exited with status " << status;
}

TEST(LandlockTest, NonDirectoryFileRules) {
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  Cleanup close_ruleset([ruleset_fd]() { close(ruleset_fd); });

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int reg_fd = open(file.path().c_str(), O_RDONLY);
  ASSERT_THAT(reg_fd, SyscallSucceeds());
  Cleanup close_reg([reg_fd]() { close(reg_fd); });

  // Adding directory creation permission on regular file -> EINVAL.
  struct landlock_path_beneath_attr invalid_path_attr = {};
  invalid_path_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_DIR;
  invalid_path_attr.parent_fd = reg_fd;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &invalid_path_attr, 0),
              SyscallFailsWithErrno(EINVAL));

  // Adding file-valid permission on regular file -> Succeeds.
  struct landlock_path_beneath_attr valid_path_attr = {};
  valid_path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  valid_path_attr.parent_fd = reg_fd;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &valid_path_attr, 0),
              SyscallSucceeds());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
