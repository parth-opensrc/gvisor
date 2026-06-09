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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

#ifndef SO_MARK
#define SO_MARK 36
#endif

#ifndef SO_RCVMARK
#define SO_RCVMARK 75
#endif

namespace gvisor {
namespace testing {

namespace {

TEST(SocketMarkTest, GetSetMark) {
  const bool has_cap = ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)) ||
                       ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN));
  SKIP_IF(!has_cap);

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  int val = -1;
  socklen_t len = sizeof(val);
  ASSERT_THAT(getsockopt(fd.get(), SOL_SOCKET, SO_MARK, &val, &len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(len, sizeof(val));
  EXPECT_EQ(val, 0);

  int rcvval = -1;
  len = sizeof(rcvval);
  ASSERT_THAT(getsockopt(fd.get(), SOL_SOCKET, SO_RCVMARK, &rcvval, &len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(len, sizeof(rcvval));
  EXPECT_EQ(rcvval, 0);

  // Set mark.
  int new_mark = 1234;
  ASSERT_THAT(
      setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &new_mark, sizeof(new_mark)),
      SyscallSucceeds());

  val = -1;
  len = sizeof(val);
  ASSERT_THAT(getsockopt(fd.get(), SOL_SOCKET, SO_MARK, &val, &len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(val, new_mark);

  // Set rcvmark.
  int new_rcvmark = 1;
  ASSERT_THAT(setsockopt(fd.get(), SOL_SOCKET, SO_RCVMARK, &new_rcvmark,
                         sizeof(new_rcvmark)),
              SyscallSucceeds());

  rcvval = -1;
  len = sizeof(rcvval);
  ASSERT_THAT(getsockopt(fd.get(), SOL_SOCKET, SO_RCVMARK, &rcvval, &len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(rcvval, 1);
}

TEST(SocketMarkTest, SetMarkNoCapability) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Drop both CAP_NET_RAW and CAP_NET_ADMIN.
  AutoCapability cap1(CAP_NET_RAW, false);
  AutoCapability cap2(CAP_NET_ADMIN, false);

  int new_mark = 1234;
  ASSERT_THAT(
      setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &new_mark, sizeof(new_mark)),
      SyscallFailsWithErrno(EPERM));
}

TEST(SocketMarkTest, LoopbackMarkPropagation) {
  const bool has_cap = ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)) ||
                       ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN));
  SKIP_IF(!has_cap);

  FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  FileDescriptor receiver =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in addr_rec = {};
  addr_rec.sin_family = AF_INET;
  addr_rec.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_rec.sin_port = 0;

  ASSERT_THAT(
      bind(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
           sizeof(addr_rec)),
      SyscallSucceeds());

  socklen_t addr_len = sizeof(addr_rec);
  ASSERT_THAT(
      getsockname(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
                  &addr_len),
      SyscallSucceeds());

  // Enable SO_RCVMARK on receiver.
  int enable = 1;
  ASSERT_THAT(setsockopt(receiver.get(), SOL_SOCKET, SO_RCVMARK, &enable,
                         sizeof(enable)),
              SyscallSucceeds());

  // Set SO_MARK on sender.
  uint32_t sender_mark = 42;
  ASSERT_THAT(setsockopt(sender.get(), SOL_SOCKET, SO_MARK, &sender_mark,
                         sizeof(sender_mark)),
              SyscallSucceeds());

  // Send packet.
  char payload[] = "hello";
  ASSERT_THAT(
      sendto(sender.get(), payload, sizeof(payload), 0,
             reinterpret_cast<struct sockaddr*>(&addr_rec), sizeof(addr_rec)),
      SyscallSucceedsWithValue(sizeof(payload)));

  // Receive packet.
  char recv_buf[32];
  struct iovec iov = {};
  iov.iov_base = recv_buf;
  iov.iov_len = sizeof(recv_buf);

  char control_buf[CMSG_SPACE(sizeof(uint32_t))] = {};
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf;
  msg.msg_controllen = sizeof(control_buf);

  ASSERT_THAT(recvmsg(receiver.get(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(payload)));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SO_MARK);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(uint32_t)));
  EXPECT_EQ(*reinterpret_cast<uint32_t*>(CMSG_DATA(cmsg)), sender_mark);
}

TEST(SocketMarkTest, LoopbackMarkOverride) {
  const bool has_cap = ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)) ||
                       ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN));
  SKIP_IF(!has_cap);

  FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  FileDescriptor receiver =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in addr_rec = {};
  addr_rec.sin_family = AF_INET;
  addr_rec.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_rec.sin_port = 0;

  ASSERT_THAT(
      bind(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
           sizeof(addr_rec)),
      SyscallSucceeds());

  socklen_t addr_len = sizeof(addr_rec);
  ASSERT_THAT(
      getsockname(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
                  &addr_len),
      SyscallSucceeds());

  // Enable SO_RCVMARK on receiver.
  int enable = 1;
  ASSERT_THAT(setsockopt(receiver.get(), SOL_SOCKET, SO_RCVMARK, &enable,
                         sizeof(enable)),
              SyscallSucceeds());

  // Send msg with cmsg SO_MARK override.
  char payload[] = "world";
  struct iovec iov = {};
  iov.iov_base = payload;
  iov.iov_len = sizeof(payload);

  uint32_t override_mark = 99;
  char control_buf[CMSG_SPACE(sizeof(uint32_t))] = {};
  struct msghdr msg = {};
  msg.msg_name = &addr_rec;
  msg.msg_namelen = sizeof(addr_rec);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf;
  msg.msg_controllen = sizeof(control_buf);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SO_MARK;
  *reinterpret_cast<uint32_t*>(CMSG_DATA(cmsg)) = override_mark;

  ASSERT_THAT(sendmsg(sender.get(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(payload)));

  // Receive packet.
  char recv_buf[32];
  struct iovec riov = {};
  riov.iov_base = recv_buf;
  riov.iov_len = sizeof(recv_buf);

  char rcontrol_buf[CMSG_SPACE(sizeof(uint32_t))] = {};
  struct msghdr rmsg = {};
  rmsg.msg_iov = &riov;
  rmsg.msg_iovlen = 1;
  rmsg.msg_control = rcontrol_buf;
  rmsg.msg_controllen = sizeof(rcontrol_buf);

  ASSERT_THAT(recvmsg(receiver.get(), &rmsg, 0),
              SyscallSucceedsWithValue(sizeof(payload)));

  struct cmsghdr* rcmsg = CMSG_FIRSTHDR(&rmsg);
  ASSERT_NE(rcmsg, nullptr);
  EXPECT_EQ(rcmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(rcmsg->cmsg_type, SO_MARK);
  EXPECT_EQ(rcmsg->cmsg_len, CMSG_LEN(sizeof(uint32_t)));
  EXPECT_EQ(*reinterpret_cast<uint32_t*>(CMSG_DATA(rcmsg)), override_mark);
}

TEST(SocketMarkTest, LoopbackMarkOverrideNoCapability) {
  FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  FileDescriptor receiver =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in addr_rec = {};
  addr_rec.sin_family = AF_INET;
  addr_rec.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_rec.sin_port = 0;

  ASSERT_THAT(
      bind(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
           sizeof(addr_rec)),
      SyscallSucceeds());

  socklen_t addr_len = sizeof(addr_rec);
  ASSERT_THAT(
      getsockname(receiver.get(), reinterpret_cast<struct sockaddr*>(&addr_rec),
                  &addr_len),
      SyscallSucceeds());

  // Drop both CAP_NET_RAW and CAP_NET_ADMIN on sender process.
  AutoCapability cap1(CAP_NET_RAW, false);
  AutoCapability cap2(CAP_NET_ADMIN, false);

  // Send msg with cmsg SO_MARK override.
  char payload[] = "world";
  struct iovec iov = {};
  iov.iov_base = payload;
  iov.iov_len = sizeof(payload);

  uint32_t override_mark = 99;
  char control_buf[CMSG_SPACE(sizeof(uint32_t))] = {};
  struct msghdr msg = {};
  msg.msg_name = &addr_rec;
  msg.msg_namelen = sizeof(addr_rec);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf;
  msg.msg_controllen = sizeof(control_buf);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SO_MARK;
  *reinterpret_cast<uint32_t*>(CMSG_DATA(cmsg)) = override_mark;

  ASSERT_THAT(sendmsg(sender.get(), &msg, 0), SyscallFailsWithErrno(EPERM));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
