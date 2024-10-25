package engine

import "time"

type Key struct {
	MTU                      int           `yaml:"mtu"`
	Mark                     int           `yaml:"fwmark"`
	Proxy                    string        `yaml:"proxy"`
	RestAPI                  string        `yaml:"restapi"`
	Device                   string        `yaml:"device"`
	LogLevel                 string        `yaml:"loglevel"`
	Interface                string        `yaml:"interface"`
	TCPModerateReceiveBuffer bool          `yaml:"tcp-moderate-receive-buffer"`
	TCPSendBufferSize        string        `yaml:"tcp-send-buffer-size"`
	TCPReceiveBufferSize     string        `yaml:"tcp-receive-buffer-size"`
	MulticastGroups          string        `yaml:"multicast-groups"`
	TUNPreUp                 string        `yaml:"tun-pre-up"`
	TUNPostUp                string        `yaml:"tun-post-up"`
	UDPTimeout               time.Duration `yaml:"udp-timeout"`
	DNSMode                  string        `yaml:"dns-mode"`
	DNSListenAddress         string        `yaml:"dns-listen-addr"`
	DNSUpstream              string        `yaml:"dns-upstream"`
	DNSUpstreamCache         bool          `yaml:"dns-upstream-cache"`
	FakeDNSIPv4CIDR          string        `yaml:"fakedns-ipv4-cidr"`
	FakeDNSRedirectUpstream  bool          `yaml:"fakedns-redirect-upstream"`
}
