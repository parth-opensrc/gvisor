// Copyright 2020 The gVisor Authors.
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

// clang-format off
#include <time.h>
#include <sys/socket.h>
// clang-format on
#include <linux/capability.h>
#include <linux/errqueue.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstdio>
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
#include "test/syscalls/linux/iptables.h"
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
constexpr char kErrorTarget[] = "ERROR";
constexpr size_t kEmptyStandardEntrySize =
    sizeof(struct ip6t_entry) + sizeof(struct xt_standard_target);
constexpr size_t kEmptyErrorEntrySize =
    sizeof(struct ip6t_entry) + sizeof(struct xt_error_target);

using ::testing::AnyOf;

TEST(IP6TablesBasic, FailSockoptNonRaw) {
  // Even if the user has CAP_NET_RAW, they shouldn't be able to use the
  // ip6tables sockopts with a non-raw socket.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  EXPECT_THAT(getsockopt(sock, SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOPROTOOPT));

  EXPECT_THAT(close(sock), SyscallSucceeds());
}

TEST(IP6TablesBasic, GetInfoErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info) - 1;
  EXPECT_THAT(getsockopt(sock, SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IP6TablesBasic, GetEntriesErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ip6t_get_entries entries = {};
  socklen_t entries_size = sizeof(struct ip6t_get_entries) - 1;
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(EINVAL));
}

TEST(IP6TablesBasic, GetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "REDIRECT");
  rev.revision = 0;

  // Revision 0 exists.
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  // Revisions > 0 don't exist.
  rev.revision = 1;
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallFailsWithErrno(EPROTONOSUPPORT));
}

// This tests the initial state of a machine with empty ip6tables via
// getsockopt(IP6T_SO_GET_INFO). We don't have a guarantee that the iptables are
// empty when running in native, but we can test that gVisor has the same
// initial state that a newly-booted Linux machine would have.
TEST(IP6TablesTest, InitialInfo) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_RAW, IPPROTO_RAW));

  // Get info via sockopt.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(
      getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
      SyscallSucceeds());

  // The nat table supports PREROUTING, and OUTPUT.
  unsigned int valid_hooks =
      (1 << NF_IP6_PRE_ROUTING) | (1 << NF_IP6_LOCAL_OUT) |
      (1 << NF_IP6_POST_ROUTING) | (1 << NF_IP6_LOCAL_IN);
  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Each chain consists of an empty entry with a standard target..
  EXPECT_EQ(info.hook_entry[NF_IP6_PRE_ROUTING], 0);
  EXPECT_EQ(info.hook_entry[NF_IP6_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.hook_entry[NF_IP6_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.hook_entry[NF_IP6_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // The underflow points are the same as the entry points.
  EXPECT_EQ(info.underflow[NF_IP6_PRE_ROUTING], 0);
  EXPECT_EQ(info.underflow[NF_IP6_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.underflow[NF_IP6_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.underflow[NF_IP6_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // One entry for each chain, plus an error entry at the end.
  EXPECT_EQ(info.num_entries, 5);

  EXPECT_EQ(info.size, 4 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kNatTablename), 0);
}

// This tests the initial state of a machine with empty ip6tables via
// getsockopt(IP6T_SO_GET_ENTRIES). We don't have a guarantee that the iptables
// are empty when running in native, but we can test that gVisor has the same
// initial state that a newly-booted Linux machine would have.
TEST(IP6TablesTest, InitialEntries) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_RAW, IPPROTO_RAW));

  // Get info via sockopt.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(
      getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
      SyscallSucceeds());

  // Use info to get entries.
  socklen_t entries_size = sizeof(struct ip6t_get_entries) + info.size;
  struct ip6t_get_entries* entries =
      static_cast<struct ip6t_get_entries*>(malloc(entries_size));
  snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  entries->size = info.size;
  ASSERT_THAT(getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_ENTRIES, entries,
                         &entries_size),
              SyscallSucceeds());

  // Verify the name and size.
  ASSERT_EQ(info.size, entries->size);
  ASSERT_EQ(strcmp(entries->name, kNatTablename), 0);

  // Verify that the entrytable is 4 entries with accept targets and no matches
  // followed by a single error target.
  size_t entry_offset = 0;
  while (entry_offset < entries->size) {
    struct ip6t_entry* entry = reinterpret_cast<struct ip6t_entry*>(
        reinterpret_cast<char*>(entries->entrytable) + entry_offset);

    // ipv6 should be zeroed.
    struct ip6t_ip6 zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    ASSERT_EQ(memcmp(static_cast<void*>(&zeroed),
                     static_cast<void*>(&entry->ipv6), sizeof(zeroed)),
              0);

    // target_offset should be zero.
    EXPECT_EQ(entry->target_offset, sizeof(ip6t_entry));

    if (entry_offset < kEmptyStandardEntrySize * 4) {
      // The first 4 entries are standard targets
      struct xt_standard_target* target =
          reinterpret_cast<struct xt_standard_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyStandardEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, ""), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      // This is what's returned for an accept verdict. I don't know why.
      EXPECT_EQ(target->verdict, -NF_ACCEPT - 1);
    } else {
      // The last entry is an error target
      struct xt_error_target* target =
          reinterpret_cast<struct xt_error_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyErrorEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, kErrorTarget), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      EXPECT_EQ(strcmp(target->errorname, kErrorTarget), 0);
    }

    entry_offset += entry->next_offset;
    break;
  }

  free(entries);
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
      Socket(/*family=*/AF_INET6, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
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
  ASSERT_THAT(
      getsockopt(getsockopt_args.sock, SOL_IPV6, getsockopt_args.optname,
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
        TEST_CHECK_ERRNO(getsockopt(sock_fd, SOL_IPV6, optname, optval, optlen),
                         EPERM);
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    GetSockOptRequiresCapNetAdminTests, GetSockOptRequiresCapNetAdminTest,
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
                args.optname = IP6T_SO_GET_INFO;
                args.optval = std::move(info_buffer);
                args.optlen = sizeof(ipt_getinfo);
                return args;
              }},
         {.test_name = "GetEntries",
          .generate_sockopt_args = [](int sock) -> absl::StatusOr<SockOptArgs> {
            socklen_t get_info_optlen = sizeof(ipt_getinfo);
            ipt_getinfo get_info;
            snprintf(get_info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            EXPECT_THAT(getsockopt(sock, /*level=*/SOL_IPV6, IP6T_SO_GET_INFO,
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
                .optname = IP6T_SO_GET_ENTRIES,
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
                    .optname = IP6T_SO_GET_REVISION_TARGET,
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
                    .optname = IP6T_SO_GET_REVISION_MATCH,
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
      Socket(/*domain=*/AF_INET6, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& setsockopt_args = *args_or_status;
  // Validate that the socket creator either succeeds or fails with EINVAL,
  // but not with EPERM.
  ASSERT_THAT(setsockopt(setsockopt_args.sock, /*level=*/SOL_IPV6,
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
            setsockopt(sock_fd, /*level=*/SOL_IPV6, optname, optval, *optlen),
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
                args.optname = IP6T_SO_SET_REPLACE;
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

struct TcpV6PseudoHdr {
  in6_addr src_ip;
  in6_addr dest_ip;
  uint32_t tcp_len;
  char zero[3];
  char protocol;
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

uint16_t TCPv6Checksum(struct ip6_hdr ip6hdr, struct tcphdr tcphdr,
                       const char* payload, ssize_t payload_len) {
  struct TcpV6PseudoHdr phdr = {};
  phdr.src_ip = ip6hdr.ip6_src;
  phdr.dest_ip = ip6hdr.ip6_dst;
  phdr.tcp_len = htonl(sizeof(tcphdr) + payload_len);
  phdr.protocol = IPPROTO_TCP;

  ssize_t buf_size = sizeof(phdr) + sizeof(tcphdr) + payload_len;
  std::vector<char> buf(buf_size);
  memcpy(buf.data(), &phdr, sizeof(phdr));
  memcpy(buf.data() + sizeof(phdr), &tcphdr, sizeof(tcphdr));
  if (payload_len > 0) {
    memcpy(buf.data() + sizeof(phdr) + sizeof(tcphdr), payload, payload_len);
  }

  return ComputeChecksum(reinterpret_cast<uint16_t*>(buf.data()), buf_size);
}

struct Icmp6V6PseudoHdr {
  struct in6_addr src_ip;
  struct in6_addr dest_ip;
  uint32_t icmp6_len;
  uint8_t zero[3];
  uint8_t next_hdr;
} __attribute__((packed));

uint16_t ICMPv6Checksum(struct in6_addr src, struct in6_addr dst,
                        const char* icmp6_buf, ssize_t icmp6_len) {
  struct Icmp6V6PseudoHdr phdr = {};
  phdr.src_ip = src;
  phdr.dest_ip = dst;
  phdr.icmp6_len = htonl(icmp6_len);
  phdr.next_hdr = IPPROTO_ICMPV6;

  ssize_t buf_size = sizeof(phdr) + icmp6_len;
  std::vector<char> buf(buf_size);
  memcpy(buf.data(), &phdr, sizeof(phdr));
  memcpy(buf.data() + sizeof(phdr), icmp6_buf, icmp6_len);

  return ComputeChecksum(reinterpret_cast<uint16_t*>(buf.data()), buf_size);
}

TEST(IP6TablesReject, ICMP6PortUnreachable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39999;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp6-port-unreach"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons(port);
  dst.sin6_addr = in6addr_loopback;

  char send_buf[] = "test payload";
  ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char recv_buf[512];
  struct sockaddr_in6 src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  ASSERT_THAT(n, SyscallSucceeds());

  ASSERT_GE(
      n, static_cast<ssize_t>(sizeof(struct icmp6_hdr) +
                              sizeof(struct ip6_hdr) + sizeof(struct udphdr)));
  struct icmp6_hdr* icmp6 = reinterpret_cast<struct icmp6_hdr*>(recv_buf);
  EXPECT_EQ(icmp6->icmp6_type, ICMP6_DST_UNREACH);
  EXPECT_EQ(icmp6->icmp6_code, ICMP6_DST_UNREACH_NOPORT);

  struct ip6_hdr* orig_ip6 =
      reinterpret_cast<struct ip6_hdr*>(recv_buf + sizeof(struct icmp6_hdr));
  EXPECT_EQ(orig_ip6->ip6_nxt, IPPROTO_UDP);
  struct udphdr* orig_udp = reinterpret_cast<struct udphdr*>(
      recv_buf + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
  EXPECT_EQ(ntohs(orig_udp->dest), port);
}

TEST(IP6TablesReject, TCP6Reset) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39998;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  // Send TCP SYN (ACK=0) to trigger RST,ACK.
  {
    int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct ip6_hdr ip = {};
    ip.ip6_src = in6addr_loopback;
    ip.ip6_dst = in6addr_loopback;

    struct tcphdr tcp = {};
    tcp.source = htons(54321);
    tcp.dest = htons(port);
    tcp.seq = htonl(12345);
    tcp.ack_seq = 0;
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.syn = 1;
    tcp.ack = 0;
    tcp.window = htons(1024);
    tcp.check = TCPv6Checksum(ip, tcp, nullptr, 0);

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_addr = in6addr_loopback;

    ASSERT_THAT(sendto(tx_sock, &tcp, sizeof(tcp), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(tcp)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());
    ASSERT_GE(n, static_cast<ssize_t>(sizeof(struct tcphdr)));

    struct tcphdr* rx_tcp = reinterpret_cast<struct tcphdr*>(recv_buf);

    EXPECT_EQ(ntohs(rx_tcp->dest), 54321);
    EXPECT_EQ(ntohs(rx_tcp->source), port);
    EXPECT_TRUE(rx_tcp->rst);
    EXPECT_TRUE(rx_tcp->ack);
    EXPECT_EQ(ntohl(rx_tcp->ack_seq), 12346);
  }

  // Send TCP ACK (ACK=1) to trigger RST.
  {
    int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct ip6_hdr ip = {};
    ip.ip6_src = in6addr_loopback;
    ip.ip6_dst = in6addr_loopback;

    struct tcphdr tcp = {};
    tcp.source = htons(54322);
    tcp.dest = htons(port);
    tcp.seq = htonl(12345);
    tcp.ack_seq = htonl(67890);
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.syn = 0;
    tcp.ack = 1;
    tcp.window = htons(1024);
    tcp.check = TCPv6Checksum(ip, tcp, nullptr, 0);

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_addr = in6addr_loopback;

    ASSERT_THAT(sendto(tx_sock, &tcp, sizeof(tcp), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(tcp)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());
    ASSERT_GE(n, static_cast<ssize_t>(sizeof(struct tcphdr)));

    struct tcphdr* rx_tcp = reinterpret_cast<struct tcphdr*>(recv_buf);

    EXPECT_EQ(ntohs(rx_tcp->dest), 54322);
    EXPECT_EQ(ntohs(rx_tcp->source), port);
    EXPECT_TRUE(rx_tcp->rst);
    EXPECT_EQ(ntohl(rx_tcp->seq), 67890);
  }
}

TEST(IP6TablesReject, FirstFragmentReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39996;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int on = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_IPV6, IPV6_HDRINCL, &on, sizeof(on)),
              SyscallSucceeds());

  struct ip6_hdr ip = {};
  ip.ip6_vfc = 0x60;
  ip.ip6_nxt = IPPROTO_FRAGMENT;  // extension header
  ip.ip6_plen = htons(sizeof(struct ip6_frag) + sizeof(struct tcphdr));
  ip.ip6_hlim = 64;
  ip.ip6_src = in6addr_loopback;
  ip.ip6_dst = in6addr_loopback;

  struct ip6_frag frag = {};
  frag.ip6f_nxt = IPPROTO_TCP;
  frag.ip6f_reserved = 0;
  frag.ip6f_offlg = IP6F_MORE_FRAG;  // Offset = 0, More fragments = 1
  frag.ip6f_ident = htonl(0x12345678);

  struct tcphdr tcp = {};
  tcp.source = htons(54321);
  tcp.dest = htons(port);
  tcp.seq = htonl(12345);
  tcp.ack_seq = 0;
  tcp.doff = sizeof(struct tcphdr) / 4;
  tcp.syn = 1;
  tcp.ack = 0;
  tcp.window = htons(1024);
  tcp.check = TCPv6Checksum(ip, tcp, nullptr, 0);

  char packet[sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) +
              sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &frag, sizeof(frag));
  memcpy(packet + sizeof(ip) + sizeof(frag), &tcp, sizeof(tcp));

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = 0;
  dst.sin6_addr = in6addr_loopback;

  ssize_t res = sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
  if (res < 0 && errno == EINVAL) {
    GTEST_SKIP() << "Writing to IPPROTO_RAW IPv6 socket is not supported";
  }
  ASSERT_THAT(res, SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in6 src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  ASSERT_THAT(n, SyscallSucceeds());
  ASSERT_GE(n, static_cast<ssize_t>(sizeof(struct tcphdr)));

  struct tcphdr* rx_tcp = reinterpret_cast<struct tcphdr*>(recv_buf);

  EXPECT_EQ(ntohs(rx_tcp->dest), 54321);
  EXPECT_EQ(ntohs(rx_tcp->source), port);
  EXPECT_TRUE(rx_tcp->rst);
  EXPECT_TRUE(rx_tcp->ack);
  EXPECT_EQ(ntohl(rx_tcp->ack_seq), 12346);
}

TEST(IP6TablesReject, SubsequentFragmentNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39996;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int on = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_IPV6, IPV6_HDRINCL, &on, sizeof(on)),
              SyscallSucceeds());

  struct ip6_hdr ip = {};
  ip.ip6_vfc = 0x60;
  ip.ip6_nxt = IPPROTO_FRAGMENT;  // extension header
  ip.ip6_plen = htons(sizeof(struct ip6_frag) + sizeof(struct tcphdr));
  ip.ip6_hlim = 64;
  ip.ip6_src = in6addr_loopback;
  ip.ip6_dst = in6addr_loopback;

  struct ip6_frag frag = {};
  frag.ip6f_nxt = IPPROTO_TCP;
  frag.ip6f_reserved = 0;
  frag.ip6f_offlg = htons(8 << 3);  // Offset = 8 (64 bytes), More fragments = 0
  frag.ip6f_ident = htonl(0x12345678);

  struct tcphdr tcp = {};
  tcp.source = htons(54321);
  tcp.dest = htons(port);
  tcp.seq = htonl(12345);
  tcp.ack_seq = 0;
  tcp.doff = sizeof(struct tcphdr) / 4;
  tcp.syn = 1;
  tcp.ack = 0;
  tcp.window = htons(1024);
  tcp.check = TCPv6Checksum(ip, tcp, nullptr, 0);

  char packet[sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) +
              sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &frag, sizeof(frag));
  memcpy(packet + sizeof(ip) + sizeof(frag), &tcp, sizeof(tcp));

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = 0;
  dst.sin6_addr = in6addr_loopback;

  ssize_t res = sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
  if (res < 0 && errno == EINVAL) {
    GTEST_SKIP() << "Writing to IPPROTO_RAW IPv6 socket is not supported";
  }
  ASSERT_THAT(res, SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in6 src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      << "Expected timeout for subsequent fragment, but received packet: " << n
      << " bytes, errno: " << errno;
}

TEST(IP6TablesReject, InvalidChecksumNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39995;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "tcp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "tcp-reset"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int on = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_IPV6, IPV6_HDRINCL, &on, sizeof(on)),
              SyscallSucceeds());

  struct ip6_hdr ip = {};
  ip.ip6_vfc = 0x60;
  ip.ip6_nxt = IPPROTO_TCP;
  ip.ip6_plen = htons(sizeof(struct tcphdr));
  ip.ip6_hlim = 64;
  ip.ip6_src = in6addr_loopback;
  ip.ip6_dst = in6addr_loopback;

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

  char packet[sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
  memcpy(packet, &ip, sizeof(ip));
  memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = 0;
  dst.sin6_addr = in6addr_loopback;

  ssize_t res = sendto(tx_sock, packet, sizeof(packet), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
  if (res < 0 && errno == EINVAL) {
    GTEST_SKIP() << "Writing to IPPROTO_RAW IPv6 socket is not supported";
  }
  ASSERT_THAT(res, SyscallSucceedsWithValue(sizeof(packet)));

  char recv_buf[512];
  struct sockaddr_in6 src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len);
  EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      << "Expected timeout for invalid checksum, but received packet: " << n
      << " bytes, errno: " << errno;
}

TEST(IP6TablesReject, PingPongPrevention) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port_tcp = 39997;

  // 1. TCP RST Loop Prevention.
  {
    AutoIptablesRule rule1(
        /*ipv6=*/true, "filter",
        {"INPUT", "-p", "tcp", "--dport", std::to_string(port_tcp), "-j",
         "REJECT", "--reject-with", "tcp-reset"});
    ASSERT_TRUE(rule1.Success());

    int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct ip6_hdr ip = {};
    ip.ip6_src = in6addr_loopback;
    ip.ip6_dst = in6addr_loopback;

    struct tcphdr tcp = {};
    tcp.source = htons(54323);
    tcp.dest = htons(port_tcp);
    tcp.seq = htonl(12345);
    tcp.ack_seq = 0;
    tcp.doff = sizeof(struct tcphdr) / 4;
    tcp.rst = 1;
    tcp.window = htons(1024);
    tcp.check = TCPv6Checksum(ip, tcp, nullptr, 0);

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_addr = in6addr_loopback;

    ASSERT_THAT(sendto(tx_sock, &tcp, sizeof(tcp), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(tcp)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "Expected timeout, but received packet: " << n
        << " bytes, errno: " << errno;
  }

  // 2. ICMPv6 Destination Unreachable Prevention.
  {
    AutoIptablesRule rule2(
        /*ipv6=*/true, "filter",
        {"INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "destination-unreachable",
         "-j", "REJECT", "--reject-with", "icmp6-port-unreach"});
    ASSERT_TRUE(rule2.Success());

    int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct icmp6_hdr icmp6 = {};
    icmp6.icmp6_type = ICMP6_DST_UNREACH;
    icmp6.icmp6_code = ICMP6_DST_UNREACH_NOPORT;
    icmp6.icmp6_cksum = 0;

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_addr = in6addr_loopback;

    ASSERT_THAT(sendto(tx_sock, &icmp6, sizeof(icmp6), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(icmp6)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "Expected timeout, but received packet: " << n
        << " bytes, errno: " << errno;
  }

  // 3. Normal ICMPv6 Echo Request.
  {
    AutoIptablesRule rule3(
        /*ipv6=*/true, "filter",
        {"INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j",
         "REJECT", "--reject-with", "icmp6-port-unreach"});
    ASSERT_TRUE(rule3.Success());

    int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct sockaddr_in6 src_addr = {};
    src_addr.sin6_family = AF_INET6;
    src_addr.sin6_addr = in6addr_loopback;
    ASSERT_THAT(bind(rx_sock, reinterpret_cast<struct sockaddr*>(&src_addr),
                     sizeof(src_addr)),
                SyscallSucceeds());

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    ASSERT_THAT(bind(tx_sock, reinterpret_cast<struct sockaddr*>(&src_addr),
                     sizeof(src_addr)),
                SyscallSucceeds());

    struct icmp6_hdr icmp6 = {};
    icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6.icmp6_code = 0;
    icmp6.icmp6_cksum = 0;

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_addr = in6addr_loopback;

    ASSERT_THAT(sendto(tx_sock, &icmp6, sizeof(icmp6), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(icmp6)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    bool got_unreach = false;
    for (int i = 0; i < 5; i++) {
      if (n < 0) break;
      struct icmp6_hdr* rx_icmp6 =
          reinterpret_cast<struct icmp6_hdr*>(recv_buf);
      if (rx_icmp6->icmp6_type == ICMP6_DST_UNREACH) {
        EXPECT_EQ(rx_icmp6->icmp6_code, ICMP6_DST_UNREACH_NOPORT);
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

struct ICMP6VariantParam {
  std::string reject_with;
  uint8_t expected_type;
  uint8_t expected_code;
};

TEST(IP6TablesReject, ICMP6Variants) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  std::vector<ICMP6VariantParam> params = {
      {"icmp6-no-route", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE},
      {"icmp6-adm-prohibited", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN},
      {"icmp6-addr-unreach", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR},
  };

  int base_port = 39980;
  for (size_t i = 0; i < params.size(); ++i) {
    int port = base_port + i;
    AutoIptablesRule rule(
        /*ipv6=*/true, "filter",
        {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
         "--reject-with", params[i].reject_with});
    ASSERT_TRUE(rule.Success());

    int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_THAT(rx_sock, SyscallSucceeds());
    FileDescriptor rx_fd(rx_sock);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
                SyscallSucceeds());

    int tx_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_THAT(tx_sock, SyscallSucceeds());
    FileDescriptor tx_fd(tx_sock);

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(port);
    dst.sin6_addr = in6addr_loopback;

    char send_buf[] = "test payload";
    ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
                SyscallSucceedsWithValue(sizeof(send_buf)));

    char recv_buf[512];
    struct sockaddr_in6 src = {};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len);
    ASSERT_THAT(n, SyscallSucceeds());

    ASSERT_GE(n, static_cast<ssize_t>(sizeof(struct icmp6_hdr) +
                                      sizeof(struct ip6_hdr) +
                                      sizeof(struct udphdr)));
    struct icmp6_hdr* icmp6 = reinterpret_cast<struct icmp6_hdr*>(recv_buf);
    EXPECT_EQ(icmp6->icmp6_type, params[i].expected_type)
        << "Failed for " << params[i].reject_with;
    EXPECT_EQ(icmp6->icmp6_code, params[i].expected_code)
        << "Failed for " << params[i].reject_with;
  }
}

TEST(IP6TablesReject, MulticastNoReject) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39979;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp6-port-unreach"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  // Send to Multicast.
  {
    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(port);
    // Link-local all-nodes multicast address: ff02::1
    dst.sin6_addr.s6_addr[0] = 0xff;
    dst.sin6_addr.s6_addr[1] = 0x02;
    dst.sin6_addr.s6_addr[15] = 0x01;

    char send_buf[] = "test payload";
    ssize_t res = sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
    if (res >= 0) {
      char recv_buf[512];
      struct sockaddr_in6 src = {};
      socklen_t src_len = sizeof(src);
      ssize_t n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
      EXPECT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
          << "Expected timeout for multicast, but received packet: " << n
          << " bytes, errno: " << errno;
    }
  }
}

TEST(IP6TablesReject, ManipulationRequiresCapabilities) {
  EXPECT_THAT(InForkedProcess([]() {
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER));
                bool res = RunIptablesCmd(
                    /*ipv6=*/true,
                    {"-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport",
                     "39999", "-j", "REJECT", "--reject-with", "tcp-reset"});
                TEST_CHECK(!res);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(IP6TablesReject, InvalidHooks) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  EXPECT_FALSE(RunIptablesCmd(
      /*ipv6=*/true,
      {"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "--dport", "39999",
       "-j", "REJECT", "--reject-with", "tcp-reset"}));

  EXPECT_FALSE(RunIptablesCmd(
      /*ipv6=*/true,
      {"-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--dport", "39999",
       "-j", "REJECT", "--reject-with", "tcp-reset"}));
}

TEST(IP6TablesReject, RecvErrorPortUnreachable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int port = 39978;

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "udp", "--dport", std::to_string(port), "-j", "REJECT",
       "--reject-with", "icmp6-port-unreach"});
  ASSERT_TRUE(rule.Success());

  int tx_sock = socket(AF_INET6, SOCK_DGRAM, 0);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  int v = 1;
  ASSERT_THAT(setsockopt(tx_sock, SOL_IPV6, IPV6_RECVERR, &v, sizeof(v)),
              SyscallSucceeds());

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons(port);
  dst.sin6_addr = in6addr_loopback;

  char send_buf[] = "test payload";
  ASSERT_THAT(sendto(tx_sock, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char got[512];
  struct iovec iov;
  iov.iov_base = reinterpret_cast<void*>(got);
  iov.iov_len = sizeof(got);

  size_t control_buf_len =
      CMSG_SPACE(sizeof(sock_extended_err) + sizeof(struct sockaddr_in6));
  std::vector<char> control_buf(control_buf_len);
  struct sockaddr_in6 remote = {};
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
  EXPECT_EQ(cmsg->cmsg_level, SOL_IPV6);
  EXPECT_EQ(cmsg->cmsg_type, IPV6_RECVERR);

  struct sock_extended_err* serr =
      reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cmsg));
  EXPECT_EQ(serr->ee_origin, SO_EE_ORIGIN_ICMP6);
  EXPECT_EQ(serr->ee_type, ICMP6_DST_UNREACH);
  EXPECT_EQ(serr->ee_code, ICMP6_DST_UNREACH_NOPORT);
}

TEST(IP6TablesReject, OddLengthPayloadChecksum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  AutoIptablesRule rule(
      /*ipv6=*/true, "filter",
      {"INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j",
       "REJECT", "--reject-with", "icmp6-port-unreach"});
  ASSERT_TRUE(rule.Success());

  int rx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  ASSERT_THAT(rx_sock, SyscallSucceeds());
  FileDescriptor rx_fd(rx_sock);

  struct sockaddr_in6 src_addr = {};
  src_addr.sin6_family = AF_INET6;
  src_addr.sin6_addr = in6addr_loopback;
  ASSERT_THAT(bind(rx_sock, reinterpret_cast<struct sockaddr*>(&src_addr),
                   sizeof(src_addr)),
              SyscallSucceeds());

  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  ASSERT_THAT(setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  int tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  ASSERT_THAT(tx_sock, SyscallSucceeds());
  FileDescriptor tx_fd(tx_sock);

  ASSERT_THAT(bind(tx_sock, reinterpret_cast<struct sockaddr*>(&src_addr),
                   sizeof(src_addr)),
              SyscallSucceeds());

  char icmp6_payload[sizeof(struct icmp6_hdr) + 1] = {};
  struct icmp6_hdr* icmp6 = reinterpret_cast<struct icmp6_hdr*>(icmp6_payload);
  icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_cksum = 0;
  icmp6_payload[sizeof(struct icmp6_hdr)] = 'A';

  icmp6->icmp6_cksum = ICMPv6Checksum(in6addr_loopback, in6addr_loopback,
                                      icmp6_payload, sizeof(icmp6_payload));

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  dst.sin6_port = 0;
  dst.sin6_addr = in6addr_loopback;

  ASSERT_THAT(sendto(tx_sock, icmp6_payload, sizeof(icmp6_payload), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(icmp6_payload)));

  char recv_buf[512];
  struct sockaddr_in6 src = {};
  socklen_t src_len = sizeof(src);
  ssize_t n = 0;
  bool got_unreach = false;
  for (int i = 0; i < 5; i++) {
    n = recvfrom(rx_sock, recv_buf, sizeof(recv_buf), 0,
                 reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) {
      break;
    }
    if (n < static_cast<ssize_t>(sizeof(struct icmp6_hdr))) {
      continue;
    }
    struct icmp6_hdr* rx_icmp6 = reinterpret_cast<struct icmp6_hdr*>(recv_buf);
    if (rx_icmp6->icmp6_type == ICMP6_DST_UNREACH &&
        rx_icmp6->icmp6_code == ICMP6_DST_UNREACH_NOPORT) {
      got_unreach = true;

      uint16_t received_checksum = rx_icmp6->icmp6_cksum;
      rx_icmp6->icmp6_cksum = 0;
      uint16_t computed_checksum =
          ICMPv6Checksum(src.sin6_addr, in6addr_loopback, recv_buf, n);
      EXPECT_EQ(received_checksum, computed_checksum);
      break;
    }
  }
  EXPECT_TRUE(got_unreach);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
