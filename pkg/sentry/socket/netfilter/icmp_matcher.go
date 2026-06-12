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

const matcherNameICMP = "icmp"

func init() {
	registerMatchMaker(icmpMarshaler{})
}

// icmpMarshaler implements matchMaker for ICMP matching.
type icmpMarshaler struct{}

// name implements matchMaker.name.
func (icmpMarshaler) name() string {
	return matcherNameICMP
}

func (icmpMarshaler) revision() uint8 {
	return 0
}

// marshal implements matchMaker.marshal.
func (icmpMarshaler) marshal(mr matcher) []byte {
	matcher := mr.(*ICMPMatcher)
	xticmp := linux.IPTICMP{
		Type:     matcher.icmpType,
		Code:     matcher.code,
		Invflags: matcher.invFlags,
	}
	return marshalEntryMatch(matcherNameICMP, marshal.Marshal(&xticmp))
}

// unmarshal implements matchMaker.unmarshal.
func (icmpMarshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfIPTICMP {
		return nil, fmt.Errorf("buf has insufficient size for ICMP match: %d", len(buf))
	}

	var matchData linux.IPTICMP
	matchData.UnmarshalUnsafe(buf)
	nflog("parseMatchers: parsed IPTICMP: %+v", matchData)

	if filter.Protocol != header.ICMPv4ProtocolNumber {
		return nil, fmt.Errorf("ICMP matching is only valid for protocol %d", header.ICMPv4ProtocolNumber)
	}

	return &ICMPMatcher{
		icmpType: matchData.Type,
		code:     matchData.Code,
		invFlags: matchData.Invflags,
	}, nil
}

// ICMPMatcher matches ICMP packets. It implements Matcher.
type ICMPMatcher struct {
	icmpType uint8
	code     [2]uint8
	invFlags uint8
}

// name implements matcher.name.
func (*ICMPMatcher) name() string {
	return matcherNameICMP
}

// revision implements matcher.revision.
func (*ICMPMatcher) revision() uint8 {
	return 0
}

// Match implements Matcher.Match.
func (im *ICMPMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		netHeader := header.IPv4(pkt.NetworkHeader().Slice())
		if netHeader.TransportProtocol() != header.ICMPv4ProtocolNumber {
			return false, false
		}

		// We don't match fragments.
		if frag := netHeader.FragmentOffset(); frag != 0 {
			if frag == 1 {
				return false, true
			}
			return false, false
		}

	default:
		// We don't know/support this network protocol for IPv4 ICMP matching.
		return false, false
	}

	icmpHeader := header.ICMPv4(peekTransportHeader(pkt, header.ICMPv4MinimumSize))
	if len(icmpHeader) < header.ICMPv4MinimumSize {
		return false, true
	}

	t := uint8(icmpHeader.Type())
	c := uint8(icmpHeader.Code())

	invert := im.invFlags&linux.IPT_ICMP_INV != 0
	matched := im.icmpType == 0xFF || (t == im.icmpType && c >= im.code[0] && c <= im.code[1])
	return matched != invert, false
}
