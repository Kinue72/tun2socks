package dns

import (
	"context"
	"errors"
	D "github.com/miekg/dns"
	singdns "github.com/sagernet/sing-dns"
	"github.com/xjasonlyu/tun2socks/v2/common/sockopt"
	"github.com/xjasonlyu/tun2socks/v2/component/fakeip"
	"github.com/xjasonlyu/tun2socks/v2/component/trie"
	"github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"net"
	"net/netip"
	"strings"
	"time"
)

var server *D.Server

type HandleMode int

const (
	VirtualMode HandleMode = iota
	UpstreamMode
)

type ServerOption struct {
	Mode             HandleMode
	ListenAddress    string
	VirtualRange     netip.Prefix
	UpstreamServer   string
	EnableCache      bool
	RedirectUpstream bool
	Dialer           proxy.Dialer
}

func (options *ServerOption) Start() (err error) {
	if options.ListenAddress == "" {
		return errors.New("empty listen address")
	}

	if options.Mode == UpstreamMode || options.RedirectUpstream {
		if err = createSingDnsClient(options.UpstreamServer, !options.EnableCache, options.Dialer); err != nil {
			return err
		}
	}

	if options.Mode == VirtualMode {
		virtualPool, err = fakeip.New(fakeip.Options{
			IPNet: options.VirtualRange,
			Host:  trie.New(),
			Size:  1000,
		})
		if err != nil {
			return err
		}
	}

	if server != nil {
		_ = server.Shutdown()
	}

	defer func() {
		if err != nil {
			log.Errorf("Start DNS server error: %s", err.Error())
		}
	}()

	_, port, err := net.SplitHostPort(options.ListenAddress)
	if port == "0" || port == "" || err != nil {
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", options.ListenAddress)
	if err != nil {
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}

	err = sockopt.UDPReuseaddr(udpConn)
	if err != nil {
		log.Warnf("Failed to Reuse UDP Address: %s", err)

		err = nil
	}

	server = &D.Server{Addr: options.ListenAddress, PacketConn: udpConn, Handler: options}

	go func() {
		err = server.ActivateAndServe()
	}()

	log.Infof("DNS server listening at: %s", udpConn.LocalAddr().String())

	return nil
}

func (options *ServerOption) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	msg, err := options.serveDnsInternal(r)
	if err != nil {
		msg = r.Copy()
		msg.Response = true
		msg.Rcode = D.RcodeServerFailure
	}

	msg.Compress = true
	_ = w.WriteMsg(msg)
}

func (options *ServerOption) serveDnsInternal(r *D.Msg) (*D.Msg, error) {
	if len(r.Question) == 0 {
		return nil, errors.New("at least one question is required")
	}

	question := r.Question[0]

	if options.Mode == VirtualMode {
		if question.Qtype == D.TypeA {
			host := strings.TrimRight(question.Name, ".")
			msg := r.Copy()

			rr := &D.A{}
			rr.Hdr = D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600}
			ip := virtualPool.Lookup(host)
			rr.A = ip.AsSlice()
			msg.Answer = []D.RR{rr}

			setMsgTTL(msg, 1)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.RecursionAvailable = true
			msg.Response = true

			return msg, nil
		}

		if !options.RedirectUpstream {
			return nil, errors.New("redirect upstream disabled")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	return client.Exchange(ctx, transport, r, singdns.DomainStrategyAsIS)
}
