// Copyright 2019 The gVisor Authors.
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

#include "test/syscalls/linux/iptables.h"

#include <arpa/inet.h>
#include <linux/capability.h>
#include <linux/errqueue.h>
#include <linux/netfilter/x_tables.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kNatTablename[] = "nat";
constexpr char kRawTablename[] = "raw";
constexpr char kErrorTarget[] = "ERROR";
constexpr size_t kEmptyStandardEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_standard_target);
constexpr size_t kEmptyErrorEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_error_target);

using ::testing::AnyOf;

TEST(IPTablesBasic, CreateSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, FailSockoptNonRaw) {
  // Even if the user has CAP_NET_RAW, they shouldn't be able to use the
  // iptables sockopts with a non-raw socket.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  EXPECT_THAT(getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOPROTOOPT));

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, GetInfoErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info) - 1;
  ASSERT_THAT(getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, GetEntriesErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_get_entries entries = {};
  socklen_t entries_size = sizeof(struct ipt_get_entries) - 1;
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  ASSERT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, OriginalDstErrors) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_STREAM, 0), SyscallSucceeds());

  // Sockets not affected by NAT should fail to find an original destination.
  struct sockaddr_in addr = {};
  socklen_t addr_len = sizeof(addr);
  EXPECT_THAT(getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, &addr, &addr_len),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST(IPTablesBasic, GetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "REDIRECT");
  rev.revision = 0;

  // Revision 0 exists.
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  // Revisions > 0 don't exist.
  rev.revision = 1;
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallFailsWithErrno(EPROTONOSUPPORT));
}

// Fixture for iptables tests.
class IPTablesTest : public ::testing::Test {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // The socket via which to manipulate iptables.
  int s_;
};

void IPTablesTest::SetUp() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(s_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), SyscallSucceeds());
}

void IPTablesTest::TearDown() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  EXPECT_THAT(close(s_), SyscallSucceeds());
}

// This tests the initial state of a machine with empty iptables. We don't
// have a guarantee that the iptables are empty when running in native, but we
// can test that gVisor has the same initial state that a newly-booted Linux
// machine would have.
TEST_F(IPTablesTest, InitialState) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  //
  // Get info via sockopt.
  //
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // The nat table supports PREROUTING, and OUTPUT.
  unsigned int valid_hooks = (1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_LOCAL_OUT) |
                             (1 << NF_IP_POST_ROUTING) | (1 << NF_IP_LOCAL_IN);

  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Each chain consists of an empty entry with a standard target..
  EXPECT_EQ(info.hook_entry[NF_IP_PRE_ROUTING], 0);
  EXPECT_EQ(info.hook_entry[NF_IP_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.hook_entry[NF_IP_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.hook_entry[NF_IP_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // The underflow points are the same as the entry points.
  EXPECT_EQ(info.underflow[NF_IP_PRE_ROUTING], 0);
  EXPECT_EQ(info.underflow[NF_IP_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.underflow[NF_IP_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.underflow[NF_IP_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // One entry for each chain, plus an error entry at the end.
  EXPECT_EQ(info.num_entries, 5);

  EXPECT_EQ(info.size, 4 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kNatTablename), 0);

  //
  // Use info to get entries.
  //
  socklen_t entries_size = sizeof(struct ipt_get_entries) + info.size;
  struct ipt_get_entries* entries =
      static_cast<struct ipt_get_entries*>(malloc(entries_size));
  snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  entries->size = info.size;
  ASSERT_THAT(
      getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, entries, &entries_size),
      SyscallSucceeds());

  // Verify the name and size.
  ASSERT_EQ(info.size, entries->size);
  ASSERT_EQ(strcmp(entries->name, kNatTablename), 0);

  // Verify that the entrytable is 4 entries with accept targets and no
  // matches followed by a single error target.
  size_t entry_offset = 0;
  while (entry_offset < entries->size) {
    struct ipt_entry* entry = reinterpret_cast<struct ipt_entry*>(
        reinterpret_cast<char*>(entries->entrytable) + entry_offset);

    // ip should be zeroes.
    struct ipt_ip zeroed = {};
    EXPECT_EQ(memcmp(static_cast<void*>(&zeroed),
                     static_cast<void*>(&entry->ip), sizeof(zeroed)),
              0);

    // target_offset should be zero.
    EXPECT_EQ(entry->target_offset, sizeof(ipt_entry));

    if (entry_offset < kEmptyStandardEntrySize * 4) {
      // The first 4 entries are standard targets
      struct ipt_standard_target* target =
          reinterpret_cast<struct ipt_standard_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyStandardEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, ""), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      // This is what's returned for an accept verdict. I don't know why.
      EXPECT_EQ(target->verdict, -NF_ACCEPT - 1);
    } else {
      // The last entry is an error target
      struct ipt_error_target* target =
          reinterpret_cast<struct ipt_error_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyErrorEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, kErrorTarget), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      EXPECT_EQ(strcmp(target->errorname, kErrorTarget), 0);
    }

    entry_offset += entry->next_offset;
  }

  free(entries);
}

// Regression test for a bug where gVisor's hard-coded maxOptLen of 8KB
// silently rejected setsockopt(IPT_SO_SET_REPLACE) payloads larger than 8192
// bytes with EINVAL. Real-world workloads such as Istio service mesh generate
// nat table rulesets that commonly exceed 8KB (Istio 1.28+ produces ~13KB).
// The limit has been raised to 32KB; Linux itself uses INT_MAX.
TEST_F(IPTablesTest, LargeReplacePayload) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Get current nat table metadata.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // Read current entries.
  socklen_t orig_sz = sizeof(struct ipt_get_entries) + info.size;
  std::unique_ptr<char[]> orig_buf(new char[orig_sz]());
  struct ipt_get_entries* orig =
      reinterpret_cast<struct ipt_get_entries*>(orig_buf.get());
  snprintf(orig->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  orig->size = info.size;
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, orig, &orig_sz),
              SyscallSucceeds());

  // Compute extra entries needed to push the total setsockopt payload past 8KB.
  const size_t kMinPayload = 9 * 1024;
  size_t extra = 0;
  if (sizeof(struct ipt_replace) + info.size < kMinPayload) {
    extra = (kMinPayload - sizeof(struct ipt_replace) - info.size +
             kEmptyStandardEntrySize - 1) /
            kEmptyStandardEntrySize;
  }
  const size_t shift = extra * kEmptyStandardEntrySize;
  const size_t new_entries_size = info.size + shift;
  const unsigned int new_num_entries = info.num_entries + extra;
  const size_t buf_sz = sizeof(struct ipt_replace) + new_entries_size;

  ASSERT_GT(buf_sz, 8192u);

  // Build ipt_replace buffer.
  std::unique_ptr<char[]> buf(new char[buf_sz]());
  struct ipt_replace* repl = reinterpret_cast<struct ipt_replace*>(buf.get());

  snprintf(repl->name, sizeof(repl->name), "%s", kNatTablename);
  repl->valid_hooks = info.valid_hooks;
  repl->num_entries = new_num_entries;
  repl->size = new_entries_size;
  repl->num_counters = new_num_entries;

  std::unique_ptr<struct xt_counters[]> ctrs(
      new struct xt_counters[new_num_entries]());
  repl->counters = ctrs.get();

  // Insert extra entries at the start of the PREROUTING chain. All valid
  // hook/underflow offsets shift forward by `shift` bytes to account for the
  // new entries. The PREROUTING hook_entry stays at 0 because the new entries
  // ARE the beginning of the chain.
  for (int h = 0; h < NF_IP_NUMHOOKS; h++) {
    if (info.valid_hooks & (1 << h)) {
      repl->hook_entry[h] = info.hook_entry[h] + shift;
      repl->underflow[h] = info.underflow[h] + shift;
    }
  }
  repl->hook_entry[NF_IP_PRE_ROUTING] = 0;

  // Fill extra entries: unconditional ACCEPT rules.
  char* dst = reinterpret_cast<char*>(repl->entries);
  for (size_t i = 0; i < extra; i++) {
    struct ipt_entry* e =
        reinterpret_cast<struct ipt_entry*>(dst + i * kEmptyStandardEntrySize);
    memset(e, 0, kEmptyStandardEntrySize);
    e->target_offset = sizeof(struct ipt_entry);
    e->next_offset = kEmptyStandardEntrySize;
    struct ipt_standard_target* t =
        reinterpret_cast<struct ipt_standard_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    t->verdict = -NF_ACCEPT - 1;
  }

  // Copy original entries after the extra ones.
  memcpy(dst + shift, reinterpret_cast<char*>(orig->entrytable), info.size);

  ASSERT_THAT(setsockopt(s_, SOL_IP, IPT_SO_SET_REPLACE, repl, buf_sz),
              SyscallSucceeds());

  // Restore original table to avoid side effects on other tests.
  size_t restore_sz = sizeof(struct ipt_replace) + info.size;
  std::unique_ptr<char[]> restore_buf(new char[restore_sz]());
  struct ipt_replace* restore =
      reinterpret_cast<struct ipt_replace*>(restore_buf.get());
  snprintf(restore->name, sizeof(restore->name), "%s", kNatTablename);
  restore->valid_hooks = info.valid_hooks;
  restore->num_entries = info.num_entries;
  restore->size = info.size;
  restore->num_counters = info.num_entries;
  std::unique_ptr<struct xt_counters[]> rctrs(
      new struct xt_counters[info.num_entries]());
  restore->counters = rctrs.get();
  memcpy(restore->hook_entry, info.hook_entry, sizeof(info.hook_entry));
  memcpy(restore->underflow, info.underflow, sizeof(info.underflow));
  memcpy(restore->entries, orig->entrytable, info.size);
  EXPECT_THAT(setsockopt(s_, SOL_IP, IPT_SO_SET_REPLACE, restore, restore_sz),
              SyscallSucceeds());
}

// Tests the initial state of the raw table. The raw table has PREROUTING and
// OUTPUT hooks (no INPUT, FORWARD, or POSTROUTING).
TEST_F(IPTablesTest, RawTableInitialState) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kRawTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // The raw table supports PREROUTING and OUTPUT only.
  unsigned int valid_hooks = (1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_LOCAL_OUT);
  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Two chain entries (PREROUTING, OUTPUT) plus one error entry.
  EXPECT_EQ(info.num_entries, 3);
  EXPECT_EQ(info.size, 2 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kRawTablename), 0);
}

// Tests that the CT target revision 0 is recognized.
TEST(IPTablesBasic, CTTargetGetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "CT");
  rev.revision = 0;

  // CT revision 0 should exist.
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  EXPECT_THAT(close(sock), SyscallSucceeds());
}

struct SockOptArgs {
  int sock;
  int optname;
  std::shared_ptr<char[]> optval;
  socklen_t optlen;
};

struct RequiresCapNetAdminTestParams {
  std::string test_name;
  std::function<absl::StatusOr<SockOptArgs>(int sock)> generate_sockopt_args;
};

class GetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {};

TEST_P(GetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*family=*/AF_INET, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& getsockopt_args = *args_or_status;

  // Copy the optval to a new buffer before the current process' getsockopt
  // call.
  std::unique_ptr<char[]> child_optval =
      std::make_unique<char[]>(getsockopt_args.optlen);
  std::memcpy(child_optval.get(), getsockopt_args.optval.get(),
              getsockopt_args.optlen);

  // Validate that the socket creator can successfully getsockopt.
  ASSERT_THAT(getsockopt(getsockopt_args.sock, SOL_IP, getsockopt_args.optname,
                         getsockopt_args.optval.get(), &getsockopt_args.optlen),
              SyscallSucceeds());

  // Validate that another process from a different user namespace cannot
  // getsockopt and fails with EPERM.
  EXPECT_THAT(
      InForkedProcess([sock_fd = sock.get(), optname = getsockopt_args.optname,
                       optval = child_optval.get(),
                       optlen = &getsockopt_args.optlen]() -> void {
        // unshare to remove the child's permissions in the parent's
        // user and network namespaces.
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET));
        // getsockopt is async signal safe, so it's okay to call it here.
        TEST_CHECK_ERRNO(getsockopt(sock_fd, SOL_IP, optname, optval, optlen),
                         EPERM);
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    GetSockOpt, GetSockOptRequiresCapNetAdminTest,
    ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
        {{.test_name = "GetInfo",
          .generate_sockopt_args =
              [](int sock) {
                SockOptArgs args;
                args.sock = sock;
                std::unique_ptr<char[]> info_buffer =
                    std::make_unique<char[]>(sizeof(ipt_getinfo));
                ipt_getinfo* info =
                    reinterpret_cast<ipt_getinfo*>(info_buffer.get());
                snprintf(info->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
                args.optname = IPT_SO_GET_INFO;
                args.optval = std::move(info_buffer);
                args.optlen = sizeof(ipt_getinfo);
                return args;
              }},
         {.test_name = "GetEntries",
          .generate_sockopt_args = [](int sock) -> absl::StatusOr<SockOptArgs> {
            socklen_t get_info_optlen = sizeof(ipt_getinfo);
            ipt_getinfo get_info;
            snprintf(get_info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            EXPECT_THAT(getsockopt(sock, /*level=*/SOL_IP, IPT_SO_GET_INFO,
                                   &get_info, &get_info_optlen),
                        SyscallSucceeds());
            socklen_t get_entries_optlen =
                sizeof(ipt_get_entries) + get_info.size;
            std::unique_ptr<char[]> entries_buffer =
                std::make_unique<char[]>(get_entries_optlen);
            ipt_get_entries* entries =
                reinterpret_cast<ipt_get_entries*>(entries_buffer.get());
            snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            entries->size = get_info.size;
            SockOptArgs get_entries_args = {
                .sock = sock,
                .optname = IPT_SO_GET_ENTRIES,
                .optval = std::move(entries_buffer),
                .optlen = get_entries_optlen,
            };
            return get_entries_args;
          }},
         {.test_name = "GetRevisionTarget",
          .generate_sockopt_args =
              [](int sock) {
                std::unique_ptr<char[]> rev_buffer =
                    std::make_unique<char[]>(sizeof(xt_get_revision));
                xt_get_revision* rev =
                    reinterpret_cast<xt_get_revision*>(rev_buffer.get());
                snprintf(rev->name, sizeof(rev->name), "REDIRECT");
                rev->revision = 0;
                return SockOptArgs{
                    .sock = sock,
                    .optname = IPT_SO_GET_REVISION_TARGET,
                    .optval = std::move(rev_buffer),
                    .optlen = sizeof(xt_get_revision),
                };
              }},
         {.test_name = "GetRevisionMatch",
          .generate_sockopt_args =
              [](int sock) {
                std::unique_ptr<char[]> rev_buffer =
                    std::make_unique<char[]>(sizeof(xt_get_revision));
                xt_get_revision* rev =
                    reinterpret_cast<xt_get_revision*>(rev_buffer.get());
                snprintf(rev->name, sizeof(rev->name), "tcp");
                rev->revision = 0;
                return SockOptArgs{
                    .sock = sock,
                    .optname = IPT_SO_GET_REVISION_MATCH,
                    .optval = std::move(rev_buffer),
                    .optlen = sizeof(xt_get_revision),
                };
              }}}),
    [](const ::testing::TestParamInfo<
        GetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });

class SetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {};

TEST_P(SetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*family=*/AF_INET, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& setsockopt_args = *args_or_status;

  // Validate that the socket creator either succeeds or fails with EINVAL,
  // but not with EPERM.
  ASSERT_THAT(setsockopt(setsockopt_args.sock, /*level=*/SOL_IP,
                         setsockopt_args.optname, setsockopt_args.optval.get(),
                         setsockopt_args.optlen),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EINVAL)));

  // Validate that another process from a different user namespace cannot
  // setsockopt and fails with EPERM.
  EXPECT_THAT(
      // Not using a copy of optval since the setsockopt accepts a const pointer
      // and so it shouldn't have modified the optval in the previous call.
      InForkedProcess([sock_fd = sock.get(), optname = setsockopt_args.optname,
                       optval = setsockopt_args.optval.get(),
                       optlen = &setsockopt_args.optlen]() {
        // unshare to remove the child's permissions in the parent's
        // user and network namespaces.
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET));
        // setsockopt is async signal safe, so it's okay to call it here.
        TEST_CHECK_ERRNO(
            setsockopt(sock_fd, /*level=*/SOL_IP, optname, optval, *optlen),
            EPERM);
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    SetSockOpt, SetSockOptRequiresCapNetAdminTest,
    ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
        {{.test_name = "SetReplace",
          .generate_sockopt_args =
              [](int sock) {
                SockOptArgs args;
                args.sock = sock;
                std::unique_ptr<char[]> replace_buffer =
                    std::make_unique<char[]>(sizeof(ipt_replace));
                ipt_replace* replace =
                    reinterpret_cast<ipt_replace*>(replace_buffer.get());
                snprintf(replace->name, sizeof(replace->name), "%s",
                         kNatTablename);
                args.optname = IPT_SO_SET_REPLACE;
                args.optval = std::move(replace_buffer);
                args.optlen = sizeof(ipt_replace);
                return args;
              }}}),
    [](const ::testing::TestParamInfo<
        SetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });
class AutoIptablesRule {
 public:
  AutoIptablesRule(bool ipv6, const std::string& table,
                   const std::vector<std::string>& args)
      : ipv6_(ipv6), table_(table), args_(args) {
    std::vector<std::string> cmd = {"-t", table_, "-A"};
    cmd.insert(cmd.end(), args_.begin(), args_.end());
    success_ = RunCmd(cmd);
    EXPECT_TRUE(success_) << "Failed to install iptables rule";
  }

  ~AutoIptablesRule() {
    if (success_) {
      std::vector<std::string> cmd = {"-t", table_, "-D"};
      cmd.insert(cmd.end(), args_.begin(), args_.end());
      EXPECT_TRUE(RunCmd(cmd)) << "Failed to clean up iptables rule";
    }
  }

  bool Success() const { return success_; }

 private:
  bool RunCmd(const std::vector<std::string>& args) {
    std::vector<std::string> paths;
    if (ipv6_) {
      paths = {"/usr/sbin/ip6tables-legacy", "/sbin/ip6tables-legacy",
               "/usr/sbin/ip6tables", "/sbin/ip6tables"};
    } else {
      paths = {"/usr/sbin/iptables-legacy", "/sbin/iptables-legacy",
               "/usr/sbin/iptables", "/sbin/iptables"};
    }

    for (const auto& path : paths) {
      std::vector<std::string> full_args = {path};
      full_args.insert(full_args.end(), args.begin(), args.end());
      ExecveArray argv(full_args);
      ExecveArray envv({"XTABLES_LOCKFILE=/tmp/xtables.lock"});
      pid_t child;
      int execve_errno = 0;
      auto cleanup_or = ForkAndExec(path, argv, envv, &child, &execve_errno);
      if (!cleanup_or.ok()) {
        continue;
      }
      if (execve_errno != 0) {
        continue;
      }
      int status;
      if (waitpid(child, &status, 0) < 0) {
        return false;
      }
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return false;
  }

  bool ipv6_;
  std::string table_;
  std::vector<std::string> args_;
  bool success_ = false;
};

struct TcpPseudoHdr {
  uint32_t src_ip;
  uint32_t dest_ip;
  char zero;
  char protocol;
  uint16_t tcp_len;
};

uint16_t ComputeChecksum(uint16_t* buf, ssize_t buf_size) {
  uint32_t total = 0;
  for (unsigned int i = 0; i < buf_size - 1; i += 2) {
    total += *buf;
    buf++;
  }
  if (buf_size % 2) {
    total += *(reinterpret_cast<unsigned char*>(buf));
  }
  while (total >> 16) {
    uint16_t lower = total & 0xffff;
    uint16_t upper = total >> 16;
    total = lower + upper;
  }
  return ~total;
}

uint16_t TCPChecksum(struct iphdr iphdr, struct tcphdr tcphdr,
                     const char* payload, ssize_t payload_len) {
  struct TcpPseudoHdr phdr = {};
  phdr.src_ip = iphdr.saddr;
  phdr.dest_ip = iphdr.daddr;
  phdr.zero = 0;
  phdr.protocol = IPPROTO_TCP;
  phdr.tcp_len = htons(sizeof(tcphdr) + payload_len);

  ssize_t buf_size = sizeof(phdr) + sizeof(tcphdr) + payload_len;
  std::vector<char> buf(buf_size);
  memcpy(buf.data(), &phdr, sizeof(phdr));
  memcpy(buf.data() + sizeof(phdr), &tcphdr, sizeof(tcphdr));
  if (payload_len > 0) {
    memcpy(buf.data() + sizeof(phdr) + sizeof(tcphdr), payload, payload_len);
  }

  return ComputeChecksum(reinterpret_cast<uint16_t*>(buf.data()), buf_size);
}

TEST(IPTablesReject, ICMPPortUnreachable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39999;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp-port-unreachable"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  char send_buf[] = "test payload";
  ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char recv_buf[512];
  struct sockaddr_in src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  ASSERT_THAT(n, SyscallSucceeds());

  ASSERT_GE(
      n, static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct icmphdr)));
  struct iphdr* ip = reinterpret_cast<struct iphdr*>(recv_buf);
  struct icmphdr* icmp =
      reinterpret_cast<struct icmphdr*>(recv_buf + ip->ihl * 4);
  EXPECT_EQ(icmp->type, ICMP_DEST_UNREACH);
  EXPECT_EQ(icmp->code, ICMP_PORT_UNREACH);

  char* orig_payload = recv_buf + ip->ihl * 4 + sizeof(struct icmphdr);
  struct iphdr* orig_ip = reinterpret_cast<struct iphdr*>(orig_payload);
  ASSERT_GE(n, static_cast<ssize_t>(ip->ihl * 4 + sizeof(struct icmphdr) +
                                    orig_ip->ihl * 4 + sizeof(struct udphdr)));
  EXPECT_EQ(orig_ip->protocol, IPPROTO_UDP);
  struct udphdr* orig_udp =
      reinterpret_cast<struct udphdr*>(orig_payload + orig_ip->ihl * 4);
  EXPECT_EQ(ntohs(orig_udp->dest), port);
}

TEST(IPTablesReject, TCPReset) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39998;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  // Send TCP SYN (ACK=0) to trigger RST,ACK.
  {
    int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct iphdr ip = {};
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = htonl(INADDR_LOOPBACK);
    ip.daddr = htonl(INADDR_LOOPBACK);

    struct tcphdr tcp = {};
    tcp.source = htons(54321);
    tcp.dest = htons(port);
    tcp.seq = htonl(12345);
    tcp.ack_seq = 0;
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.syn = 1;
    tcp.ack = 0;
    tcp.window = htons(1024);
    tcp.check = TCPChecksum(ip, tcp, nullptr, 0);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(packet)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());
    ASSERT_GE(
        n, static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct tcphdr)));

    struct iphdr* rx_ip = reinterpret_cast<struct iphdr*>(recv_buf);
    struct tcphdr* rx_tcp =
        reinterpret_cast<struct tcphdr*>(recv_buf + rx_ip->ihl * 4);

    EXPECT_EQ(ntohs(rx_tcp->dest), 54321);
    EXPECT_EQ(ntohs(rx_tcp->source), port);
    EXPECT_TRUE(rx_tcp->rst);
    EXPECT_TRUE(rx_tcp->ack);
    EXPECT_EQ(ntohl(rx_tcp->ack_seq), 12346);
  }

  // Send TCP ACK (ACK=1) to trigger RST.
  {
    int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct iphdr ip = {};
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = htonl(INADDR_LOOPBACK);
    ip.daddr = htonl(INADDR_LOOPBACK);

    struct tcphdr tcp = {};
    tcp.source = htons(54322);
    tcp.dest = htons(port);
    tcp.seq = htonl(12345);
    tcp.ack_seq = htonl(67890);
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.syn = 0;
    tcp.ack = 1;
    tcp.window = htons(1024);
    tcp.check = TCPChecksum(ip, tcp, nullptr, 0);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(packet)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());
    ASSERT_GE(
        n, static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct tcphdr)));

    struct iphdr* rx_ip = reinterpret_cast<struct iphdr*>(recv_buf);
    struct tcphdr* rx_tcp =
        reinterpret_cast<struct tcphdr*>(recv_buf + rx_ip->ihl * 4);

    EXPECT_EQ(ntohs(rx_tcp->dest), 54322);
    EXPECT_EQ(ntohs(rx_tcp->source), port);
    EXPECT_TRUE(rx_tcp->rst);
    EXPECT_EQ(ntohl(rx_tcp->seq), 67890);
  }
}

TEST(IPTablesReject, FirstFragmentReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39996;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct iphdr ip = {};
  ip.ihl = 5;
  ip.version = 4;
  ip.tos = 0;
  ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ip.id = 0;
  ip.frag_off = htons(IP_MF);  // Offset = 0, More fragments = 1
  ip.ttl = 64;
  ip.protocol = IPPROTO_TCP;
  ip.saddr = htonl(INADDR_LOOPBACK);
  ip.daddr = htonl(INADDR_LOOPBACK);

  struct tcphdr tcp = {};
  tcp.source = htons(54321);
  tcp.dest = htons(port);
  tcp.seq = htonl(12345);
  tcp.ack_seq = 0;
  tcp.doff = sizeof(struct tcphdr) / 4;
  tcp.syn = 1;
  tcp.ack = 0;
  tcp.window = htons(1024);
  tcp.check = TCPChecksum(ip, tcp, nullptr, 0);

  char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  ASSERT_THAT(n, SyscallSucceeds());
  ASSERT_GE(n,
            static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct tcphdr)));

  struct iphdr* rx_ip = reinterpret_cast<struct iphdr*>(recv_buf);
  struct tcphdr* rx_tcp =
      reinterpret_cast<struct tcphdr*>(recv_buf + rx_ip->ihl * 4);

  EXPECT_EQ(ntohs(rx_tcp->dest), 54321);
  EXPECT_EQ(ntohs(rx_tcp->source), port);
  EXPECT_TRUE(rx_tcp->rst);
  EXPECT_TRUE(rx_tcp->ack);
  EXPECT_EQ(ntohl(rx_tcp->ack_seq), 12346);
}

TEST(IPTablesReject, SubsequentFragmentNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39996;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct iphdr ip = {};
  ip.ihl = 5;
  ip.version = 4;
  ip.tos = 0;
  ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ip.id = 0;
  ip.frag_off = htons(8);  // Offset = 64 bytes (8 * 8), More fragments = 0
  ip.ttl = 64;
  ip.protocol = IPPROTO_TCP;
  ip.saddr = htonl(INADDR_LOOPBACK);
  ip.daddr = htonl(INADDR_LOOPBACK);

  struct tcphdr tcp = {};
  tcp.source = htons(54321);
  tcp.dest = htons(port);
  tcp.seq = htonl(12345);
  tcp.ack_seq = 0;
  tcp.doff = sizeof(struct tcphdr) / 4;
  tcp.syn = 1;
  tcp.ack = 0;
  tcp.window = htons(1024);
  tcp.check = TCPChecksum(ip, tcp, nullptr, 0);

  char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      << "Expected timeout for subsequent fragment, but received packet: " << n
      << " bytes, errno: " << errno;
}

TEST(IPTablesReject, InvalidChecksumNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39995;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct iphdr ip = {};
  ip.ihl = 5;
  ip.version = 4;
  ip.tos = 0;
  ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ip.id = 0;
  ip.frag_off = 0;
  ip.ttl = 64;
  ip.protocol = IPPROTO_TCP;
  ip.saddr = htonl(INADDR_LOOPBACK);
  ip.daddr = htonl(INADDR_LOOPBACK);

  struct tcphdr tcp = {};
  tcp.source = htons(54321);
  tcp.dest = htons(port);
  tcp.seq = htonl(12345);
  tcp.ack_seq = 0;
  tcp.doff = sizeof(struct tcphdr) / 4;
  tcp.syn = 1;
  tcp.ack = 0;
  tcp.window = htons(1024);
  // Set invalid checksum (do NOT compute actual checksum)
  tcp.check = 0x1234;

  char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      << "Expected timeout for invalid checksum, but received packet: " << n
      << " bytes, errno: " << errno;
}

TEST(IPTablesReject, PingPongPrevention) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port_tcp = 39997;

  // 1. TCP RST Loop Prevention.
  {
    AutoIptablesRule rule1(
        /*ipv6=*/false, "filter",
        {"INPUT", "-p", "tcp", "--dport", std::to_string(port_tcp), "-j",
         "REJECT", "--reject-with", "tcp-reset"});
    ASSERT_TRUE(rule1.Success());

    int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct iphdr ip = {};
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = htonl(INADDR_LOOPBACK);
    ip.daddr = htonl(INADDR_LOOPBACK);

    struct tcphdr tcp = {};
    tcp.source = htons(54323);
    tcp.dest = htons(port_tcp);
    tcp.seq = htonl(12345);
    tcp.ack_seq = 0;
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.rst = 1;
    tcp.window = htons(1024);
    tcp.check = TCPChecksum(ip, tcp, nullptr, 0);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port_tcp);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(packet)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "Expected timeout, but received packet: " << n
        << " bytes, errno: " << errno;
  }

  // 2. ICMP Destination Unreachable Prevention.
  {
    AutoIptablesRule rule2(
        /*ipv6=*/false, "filter",
        {"INPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j",
         "REJECT", "--reject-with", "icmp-port-unreachable"});
    ASSERT_TRUE(rule2.Success());

    int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct iphdr ip = {};
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = htonl(INADDR_LOOPBACK);
    ip.daddr = htonl(INADDR_LOOPBACK);

    struct icmphdr icmp = {};
    icmp.type = ICMP_DEST_UNREACH;
    icmp.code = ICMP_PORT_UNREACH;
    icmp.checksum = ICMPChecksum(icmp, nullptr, 0);

    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = 0;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(packet)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "Expected timeout, but received packet: " << n
        << " bytes, errno: " << errno;
  }

  // 3. Normal ICMP Echo Request.
  {
    AutoIptablesRule rule3(
        /*ipv6=*/false, "filter",
        {"INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "REJECT",
         "--reject-with", "icmp-port-unreachable"});
    ASSERT_TRUE(rule3.Success());

    int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct iphdr ip = {};
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = htonl(INADDR_LOOPBACK);
    ip.daddr = htonl(INADDR_LOOPBACK);

    struct icmphdr icmp = {};
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.checksum = ICMPChecksum(icmp, nullptr, 0);

    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = 0;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(packet)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    bool got_unreach = false;
    for (int i = 0; i < 5; i++) {
      if (n < 0) break;
      struct iphdr* rx_ip = reinterpret_cast<struct iphdr*>(recv_buf);
      struct icmphdr* rx_icmp =
          reinterpret_cast<struct icmphdr*>(recv_buf + rx_ip->ihl * 4);
      if (rx_icmp->type == ICMP_DEST_UNREACH) {
        EXPECT_EQ(rx_icmp->code, ICMP_PORT_UNREACH);
        got_unreach = true;
        break;
      }
      n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                   reinterpret_cast<struct sockaddr*>(&src), &src_len);
    }
    EXPECT_TRUE(got_unreach);
  }
}

bool RunIptablesCmd(bool ipv6, const std::vector<std::string>& args) {
  std::vector<std::string> paths;
  if (ipv6) {
    paths = {"/usr/sbin/ip6tables-legacy", "/sbin/ip6tables-legacy",
             "/usr/sbin/ip6tables", "/sbin/ip6tables"};
  } else {
    paths = {"/usr/sbin/iptables-legacy", "/sbin/iptables-legacy",
             "/usr/sbin/iptables", "/sbin/iptables"};
  }

  for (const auto& path : paths) {
    std::vector<std::string> full_args = {path};
    full_args.insert(full_args.end(), args.begin(), args.end());
    ExecveArray argv(full_args);
    ExecveArray envv({"XTABLES_LOCKFILE=/tmp/xtables.lock"});
    pid_t child;
    int execve_errno = 0;
    auto cleanup_or = ForkAndExec(path, argv, envv, &child, &execve_errno);
    if (!cleanup_or.ok()) {
      continue;
    }
    if (execve_errno != 0) {
      continue;
    }
    int status;
    if (waitpid(child, &status, 0) < 0) {
      return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }
  return false;
}

struct ICMPVariantParam {
  std::string reject_with;
  uint8_t expected_type;
  uint8_t expected_code;
};

TEST(IPTablesReject, ICMPVariants) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  std::vector<ICMPVariantParam> params = {
      {"icmp-net-unreachable", ICMP_DEST_UNREACH, ICMP_NET_UNREACH},
      {"icmp-host-unreachable", ICMP_DEST_UNREACH, ICMP_HOST_UNREACH},
      {"icmp-net-prohibited", ICMP_DEST_UNREACH, ICMP_NET_ANO},
      {"icmp-host-prohibited", ICMP_DEST_UNREACH, ICMP_HOST_ANO},
      {"icmp-admin-prohibited", ICMP_DEST_UNREACH, ICMP_PKT_FILTERED},
  };

  int base_port = 39980;
  for (size_t i = 0; i < params.size(); ++i) {
    int port = base_port + i;
    AutoIptablesRule rule(
        /*ipv6=*/false, "filter",
        {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
         "--reject-with", params[i].reject_with});
    ASSERT_TRUE(rule.Success());

    int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    char send_buf[] = "test payload";
    ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(send_buf)));

    char recv_buf[512];
    struct sockaddr_in src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());

    ASSERT_GE(
        n, static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct icmphdr)));
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(recv_buf);
    struct icmphdr* icmp =
        reinterpret_cast<struct icmphdr*>(recv_buf + ip->ihl * 4);
    EXPECT_EQ(icmp->type, params[i].expected_type)
        << "Failed for " << params[i].reject_with;
    EXPECT_EQ(icmp->code, params[i].expected_code)
        << "Failed for " << params[i].reject_with;
  }
}

TEST(IPTablesReject, BroadcastMulticastNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39979;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp-port-unreachable"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int on = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)),
              SyscallSucceeds());

  // 1. Send to Broadcast.
  {
    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);  // 255.255.255.255

    char send_buf[] = "test payload";
    ssize_t res = sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
    if (res >= 0) {
      char recv_buf[512];
      struct sockaddr_in src = {};
      socklen_t src_len = sizeof(src);
      ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
      EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
          << "Expected timeout for broadcast, but received packet: " << n
          << " bytes, errno: " << errno;
    }
  }

  // 2. Send to Multicast.
  {
    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = inet_addr("224.0.0.1");

    char send_buf[] = "test payload";
    ssize_t res = sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
    if (res >= 0) {
      char recv_buf[512];
      struct sockaddr_in src = {};
      socklen_t src_len = sizeof(src);
      ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
      EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
          << "Expected timeout for multicast, but received packet: " << n
          << " bytes, errno: " << errno;
    }
  }
}

TEST(IPTablesReject, ManipulationRequiresCapabilities) {
  EXPECT_THAT(InForkedProcess([]() {
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER));
                bool res = RunIptablesCmd(
                    /*ipv6=*/false,
                    {"-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport",
                     "39999", "-j", "REJECT", "--reject-with", "tcp-reset"});
                TEST_CHECK(!res);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(IPTablesReject, InvalidHooks) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  EXPECT_FALSE(RunIptablesCmd(
      /*ipv6=*/false,
      {"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "--dport", "39999",
       "-j", "REJECT", "--reject-with", "tcp-reset"}));

  EXPECT_FALSE(RunIptablesCmd(
      /*ipv6=*/false,
      {"-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--dport", "39999",
       "-j", "REJECT", "--reject-with", "tcp-reset"}));
}

TEST(IPTablesReject, RecvErrorPortUnreachable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39978;

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp-port-unreachable"});
  ASSERT_TRUE(rule.Success());

  int tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int v = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_IP, IP_RECVERR, &v, sizeof(v)),
              SyscallSucceeds());

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  char send_buf[] = "test payload";
  ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char got[512];
  struct iovec iov;
  iov.iov_base = reinterpret_cast<void*>(got);
  iov.iov_len = sizeof(got);

  size_t control_buf_len =
      CMSG_SPACE(sizeof(sock_extended_err) + sizeof(struct sockaddr_in));
  std::vector<char> control_buf(control_buf_len);
  struct sockaddr_in remote = {};
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = control_buf.data();
  msg.msg_controllen = control_buf_len;
  msg.msg_name = reinterpret_cast<void*>(&remote);
  msg.msg_namelen = sizeof(remote);

  struct pollfd pfd = {.fd = tx_sock, .events = POLLIN};
  int ready = poll(&pfd, 1, 1000);
  ASSERT_TRUE(ready > 0 && (pfd.revents & POLLERR));

  ASSERT_THAT(recvmsg(tx_sock, &msg, MSG_ERRQUEUE),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  EXPECT_EQ(memcmp(got, send_buf, sizeof(send_buf)), 0);
  EXPECT_NE(msg.msg_flags & MSG_ERRQUEUE, 0);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_level, SOL_IP);
  EXPECT_EQ(cmsg->cmsg_type, IP_RECVERR);

  struct sock_extended_err* serr =
      reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cmsg));
  EXPECT_EQ(serr->ee_origin, SO_EE_ORIGIN_ICMP);
  EXPECT_EQ(serr->ee_type, ICMP_DEST_UNREACH);
  EXPECT_EQ(serr->ee_code, ICMP_PORT_UNREACH);
}

TEST(IPTablesReject, OddLengthPayloadChecksum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  AutoIptablesRule rule(
      /*ipv6=*/false, "filter",
      {"INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "REJECT",
       "--reject-with", "icmp-port-unreachable"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct iphdr ip = {};
  ip.ihl = 5;
  ip.version = 4;
  ip.tos = 0;
  ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 1);
  ip.id = 0;
  ip.frag_off = 0;
  ip.ttl = 64;
  ip.protocol = IPPROTO_ICMP;
  ip.saddr = htonl(INADDR_LOOPBACK);
  ip.daddr = htonl(INADDR_LOOPBACK);

  struct icmphdr icmp = {};
  icmp.type = ICMP_ECHO;
  icmp.code = 0;

  char icmp_payload[sizeof(struct icmphdr) + 1] = {};
  memcpy(icmp_payload, &icmp, sizeof(icmp));
  icmp_payload[sizeof(struct icmphdr)] = 'A';

  struct icmphdr* temp_icmp = reinterpret_cast<struct icmphdr*>(icmp_payload);
  temp_icmp->checksum =
      ICMPChecksum(*temp_icmp, icmp_payload + sizeof(struct icmphdr), 1);

  char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + 1];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), icmp_payload, sizeof(icmp_payload));

  struct sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_port = 0;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ASSERT_THAT(sendto(tx_sock, packet, sizeof(packet), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = 0;
  bool got_unreach = false;
  for (int i = 0; i < 5; i++) {
    n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                 reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) {
      break;
    }
    if (n <
        static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct icmphdr))) {
      continue;
    }
    struct iphdr* rx_ip = reinterpret_cast<struct iphdr*>(recv_buf);
    struct icmphdr* rx_icmp =
        reinterpret_cast<struct icmphdr*>(recv_buf + rx_ip->ihl * 4);
    if (rx_icmp->type == ICMP_DEST_UNREACH &&
        rx_icmp->code == ICMP_PORT_UNREACH) {
      got_unreach = true;

      uint16_t received_checksum = rx_icmp->checksum;
      rx_icmp->checksum = 0;
      uint16_t computed_checksum = ComputeChecksum(
          reinterpret_cast<uint16_t*>(rx_icmp), n - rx_ip->ihl * 4);
      EXPECT_EQ(received_checksum, computed_checksum);
      break;
    }
  }
  EXPECT_TRUE(got_unreach);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
