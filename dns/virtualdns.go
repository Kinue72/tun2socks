package dns

import (
	D "github.com/miekg/dns"
	"github.com/xjasonlyu/tun2socks/v2/component/fakeip"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"net/netip"
)

var (
	virtualPool *fakeip.Pool
)

func ProcessMetadata(metadata *M.Metadata) bool {
	if virtualPool == nil {
		return false
	}
	dstName, found := virtualPool.LookBack(metadata.DstIP)
	if !found {
		return false
	}
	metadata.DstName = dstName
	metadata.DstIP = netip.Addr{}
	return true
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	for _, answer := range msg.Answer {
		answer.Header().Ttl = ttl
	}

	for _, ns := range msg.Ns {
		ns.Header().Ttl = ttl
	}

	for _, extra := range msg.Extra {
		extra.Header().Ttl = ttl
	}
}
