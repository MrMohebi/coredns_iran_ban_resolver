package iran_ban_resolver

import (
	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/pkg/errors"
	"net"
	"strings"
	"time"
)

func init() { plugin.Register("iran_ban_resolver", setup) }

func periodicHostsUpdate(ibr *IranBanResolver) chan bool {
	parseChan := make(chan bool)

	if ibr.reload == 0 {
		return parseChan
	}

	go func() {
		ticker := time.NewTicker(ibr.reload)
		defer ticker.Stop()
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				ibr.readHosts()
			}
		}
	}()
	return parseChan
}

// setup is the function that gets called when the config parser see the token "iran_resolver".
func setup(c *caddy.Controller) error {
	ibr, err := parseIBR(c)
	if err != nil {
		return plugin.Error("iran_ban_resolver", err)
	}

	// check required params
	if len(ibr.hostsPath) < 1 {
		return plugin.Error("iran_resolver", errors.New("hosts required!"))
	}

	parseChan := periodicHostsUpdate(ibr)

	c.OnStartup(func() error {
		ibr.readHosts()
		return nil
	})
	c.OnShutdown(func() error {
		close(parseChan)
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ibr.Next = next
		return ibr
	})

	return nil
}

// OnStartup starts a goroutines for all clients.
func (ibr *IranBanResolver) OnStartup() (err error) {
	return nil
}

// OnShutdown stops all configured clients.
func (ibr *IranBanResolver) OnShutdown() error {
	return nil
}

func parseIBR(c *caddy.Controller) (*IranBanResolver, error) {
	var (
		ibr *IranBanResolver
		err error
		i   int
	)
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		ibr, err = parseStanza(&c.Dispenser)
		if err != nil {
			return nil, err
		}
	}

	return ibr, nil
}

func parseStanza(c *caddyfile.Dispenser) (*IranBanResolver, error) {
	ibr := New()

	for c.NextBlock() {
		err := parseValue(strings.ToLower(c.Val()), ibr, c)
		if err != nil {
			return nil, err
		}
	}
	return ibr, nil
}

func parseValue(v string, ibr *IranBanResolver, c *caddyfile.Dispenser) error {
	switch v {
	case "hosts":
		return parseHostsPath(ibr, c)
	case "reload":
		return parseReload(ibr, c)
	case "resolve-from":
		return parseResolveFrom(ibr, c)
	default:
		return errors.Errorf("unknown property %v", v)
	}
}

func parseResolveFrom(ibr *IranBanResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()

	//fall to default val
	if len(v) < 2 {
		return nil
	}

	ip, err := net.ResolveUDPAddr("udp", v)
	if err != nil {
		return c.ArgErr()
	}
	ibr.resolveFrom = ip

	return nil
}

func parseReload(ibr *IranBanResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()

	//fall to default val
	if len(v) < 2 {
		return nil
	}

	reload, err := time.ParseDuration(v)
	if err != nil {
		return c.Errf("invalid duration for reload '%s'", v)
	}
	if reload < 0 {
		return c.Errf("invalid negative duration for reload '%s'", v)
	}

	ibr.reload = reload

	return nil
}

func parseHostsPath(ibr *IranBanResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()
	if len(v) < 2 {
		return errors.New("hosts file path not set!")
	}

	ibr.hostsPath = v
	return nil
}
