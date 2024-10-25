package dns

import (
	"context"
	"errors"
	singdns "github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"net"
)

type tunnelDialer struct {
	dialer proxy.Dialer
}

func (d *tunnelDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, &metadata.Metadata{
		Network: metadata.TCP,
		DstIP:   destination.Addr,
		DstName: destination.Fqdn,
		DstPort: destination.Port,
	})
}
func (d *tunnelDialer) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.dialer.DialUDP(&metadata.Metadata{
		Network: metadata.UDP,
		DstIP:   destination.Addr,
		DstName: destination.Fqdn,
		DstPort: destination.Port,
	})
}

var client *singdns.Client
var transport singdns.Transport

func createSingDnsClient(upstream string, disableCache bool, dialer proxy.Dialer) (err error) {
	if dialer == nil {
		return errors.New("socks dialer is nil")
	}

	client = singdns.NewClient(singdns.ClientOptions{
		DisableCache: disableCache,
		Logger:       logger.NOP(),
	})

	transport, err = singdns.CreateTransport(singdns.TransportOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Name:    "transport",
		Dialer:  &tunnelDialer{dialer: dialer},
		Address: upstream,
	})

	return err
}
