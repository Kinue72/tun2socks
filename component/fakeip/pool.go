package fakeip

import (
	"encoding/binary"
	"errors"
	"github.com/xjasonlyu/tun2socks/v2/component/trie"
	"net/netip"
	"strings"
	"sync"
)

type store interface {
	GetByHost(host string) (netip.Addr, bool)
	PutByHost(host string, ip netip.Addr)
	GetByIP(ip netip.Addr) (string, bool)
	PutByIP(ip netip.Addr, host string)
	DelByIP(ip netip.Addr)
	Exist(ip netip.Addr) bool
	CloneTo(store)
	FlushFakeIP() error
}

// Pool is an implementation about fake ip generator without storage
type Pool struct {
	gateway netip.Addr
	first   netip.Addr
	last    netip.Addr
	offset  netip.Addr
	cycle   bool
	mux     sync.Mutex
	host    *trie.DomainTrie
	ipnet   netip.Prefix
	store   store
}

// Lookup return a fake ip with host
func (p *Pool) Lookup(host string) netip.Addr {
	p.mux.Lock()
	defer p.mux.Unlock()

	// RFC4343: DNS Case Insensitive, we SHOULD return result with all cases.
	host = strings.ToLower(host)
	if ip, exist := p.store.GetByHost(host); exist {
		return ip
	}

	ip := p.get(host)
	p.store.PutByHost(host, ip)
	return ip
}

// LookBack return host with the fake ip
func (p *Pool) LookBack(ip netip.Addr) (string, bool) {
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.GetByIP(ip)
}

// ShouldSkipped return if domain should be skipped
func (p *Pool) ShouldSkipped(domain string) bool {
	if p.host == nil {
		return false
	}
	return p.host.Search(domain) != nil
}

// Exist returns if given ip exists in fake-ip pool
func (p *Pool) Exist(ip netip.Addr) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.Exist(ip)
}

// Gateway return gateway ip
func (p *Pool) Gateway() netip.Addr {
	return p.gateway
}

// Broadcast return the last ip
func (p *Pool) Broadcast() netip.Addr {
	return p.last
}

// IPNet return raw ipnet
func (p *Pool) IPNet() netip.Prefix {
	return p.ipnet
}

// CloneFrom clone cache from old pool
func (p *Pool) CloneFrom(o *Pool) {
	o.store.CloneTo(p.store)
}

func (p *Pool) get(host string) netip.Addr {
	p.offset = p.offset.Next()

	if !p.offset.Less(p.last) {
		p.cycle = true
		p.offset = p.first
	}

	if p.cycle || p.store.Exist(p.offset) {
		p.store.DelByIP(p.offset)
	}

	p.store.PutByIP(p.offset, host)
	return p.offset
}

func (p *Pool) FlushFakeIP() error {
	err := p.store.FlushFakeIP()
	if err == nil {
		p.cycle = false
		p.offset = p.first.Prev()
	}
	return err
}

type Options struct {
	IPNet netip.Prefix
	Host  *trie.DomainTrie
	// Size sets the maximum number of entries in memory
	Size int
}

// New return Pool instance
func New(options Options) (*Pool, error) {
	var (
		hostAddr = options.IPNet.Masked().Addr()
		gateway  = hostAddr.Next()
		first    = gateway.Next().Next().Next() // default start with 198.18.0.4
		last     = unMasked(options.IPNet)
	)

	if !options.IPNet.IsValid() || !first.IsValid() || !first.Less(last) {
		return nil, errors.New("ipnet don't have valid ip")
	}

	pool := &Pool{
		gateway: gateway,
		first:   first,
		last:    last,
		offset:  first.Prev(),
		cycle:   false,
		host:    options.Host,
		ipnet:   options.IPNet,
	}

	pool.store = newMemoryStore(options.Size)

	return pool, nil
}

func unMasked(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}

	buf := p.Addr().As16()

	hi := binary.BigEndian.Uint64(buf[:8])
	lo := binary.BigEndian.Uint64(buf[8:])

	bits := p.Bits()
	if bits <= 32 {
		bits += 96
	}

	hi = hi | ^uint64(0)>>bits
	lo = lo | ^(^uint64(0) << (128 - bits))

	binary.BigEndian.PutUint64(buf[:8], hi)
	binary.BigEndian.PutUint64(buf[8:], lo)

	addr := netip.AddrFrom16(buf)
	if p.Addr().Is4() {
		return addr.Unmap()
	}
	return addr
}
