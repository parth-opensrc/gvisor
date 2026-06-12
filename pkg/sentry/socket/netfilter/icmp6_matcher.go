// Copyright 2024 The gVisor Authors.
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

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const matcherNameICMP6 = "icmp6"

func init() {
	registerMatchMaker(icmp6Marshaler{})
}

// icmp6Marshaler implements matchMaker for ICMPv6 matching.
type icmp6Marshaler struct{}

// name implements matchMaker.name.
func (icmp6Marshaler) name() string {
	return matcherNameICMP6
}

func (icmp6Marshaler) revision() uint8 {
	return 0
}

// marshal implements matchMaker.marshal.
func (icmp6Marshaler) marshal(mr matcher) []byte {
	matcher := mr.(*ICMP6Matcher)
	xticmp6 := linux.IP6TICMP{
		Type:     matcher.icmpType,
		Code:     matcher.code,
		Invflags: matcher.invFlags,
	}
	return marshalEntryMatch(matcherNameICMP6, marshal.Marshal(&xticmp6))
}

// unmarshal implements matchMaker.unmarshal.
func (icmp6Marshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfIP6TICMP {
		return nil, fmt.Errorf("buf has insufficient size for ICMPv6 match: %d", len(buf))
	}

	var matchData linux.IP6TICMP
	matchData.UnmarshalUnsafe(buf)
	nflog("parseMatchers: parsed IP6TICMP: %+v", matchData)

	if filter.Protocol != header.ICMPv6ProtocolNumber {
		return nil, fmt.Errorf("ICMPv6 matching is only valid for protocol %d", header.ICMPv6ProtocolNumber)
	}

	return &ICMP6Matcher{
		icmpType: matchData.Type,
		code:     matchData.Code,
		invFlags: matchData.Invflags,
	}, nil
}

// ICMP6Matcher matches ICMPv6 packets. It implements Matcher.
type ICMP6Matcher struct {
	icmpType uint8
	code     [2]uint8
	invFlags uint8
}

// name implements matcher.name.
func (*ICMP6Matcher) name() string {
	return matcherNameICMP6
}

// revision implements matcher.revision.
func (*ICMP6Matcher) revision() uint8 {
	return 0
}

// Match implements Matcher.Match.
func (im *ICMP6Matcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv6ProtocolNumber:
		netHeader := header.IPv6(pkt.NetworkHeader().Slice())
		// Matches Linux net/ipv6/exthdrs_core.c:ipv6_skip_exthdr()
		transProto, _ := netHeader.TryParseTransportProtocol()
		if transProto != header.ICMPv6ProtocolNumber {
			return false, false
		}

	default:
		// We don't know/support this network protocol for IPv6 ICMPv6 matching.
		return false, false
	}

	icmpHeader := header.ICMPv6(peekTransportHeader(pkt, header.ICMPv6MinimumSize))
	if len(icmpHeader) < header.ICMPv6MinimumSize {
		return false, true
	}

	t := uint8(icmpHeader.Type())
	c := uint8(icmpHeader.Code())

	invert := im.invFlags&linux.IP6T_ICMP_INV != 0
	matched := im.icmpType == 0xFF || (t == im.icmpType && c >= im.code[0] && c <= im.code[1])
	return matched != invert, false
}
