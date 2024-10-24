package dns

import (
	"context"
	singdns "github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"net"
	"time"
)

var defaultDialer = (*tunnelDialer)(nil)

type tunnelDialer struct {
}

func (_ *tunnelDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return dialer.DialContext(ctx, network, destination.String())

}
func (_ *tunnelDialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return dialer.ListenPacket("udp", "")
}

var client *singdns.Client

var internalTransport singdns.Transport
var transport singdns.Transport

func createSingDnsClient(upstream string, disableCache bool) (err error) {
	client = singdns.NewClient(singdns.ClientOptions{
		DisableCache: disableCache,
		Logger:       logger.NOP(),
	})

	internalTransport, err = singdns.CreateTransport(singdns.TransportOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Name:    "internal_transport",
		Dialer:  defaultDialer,
		Address: "tcp://1.1.1.1",
	})

	if err != nil {
		return err
	}

	transport, err = singdns.CreateTransport(singdns.TransportOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Name:    "transport",
		Dialer:  singdns.NewDialerWrapper(defaultDialer, client, internalTransport, singdns.DomainStrategyAsIS, time.Second*15),
		Address: upstream,
	})

	return err
}
