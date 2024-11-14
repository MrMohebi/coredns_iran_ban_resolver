package iran_ban_resolver

import (
	"bufio"
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// IranBanResolver is a coredns plugin to resolve banned domains in iran.
type IranBanResolver struct {
	sync.RWMutex

	hostsPath   string
	reload      time.Duration
	resolveFrom net.Addr

	hosts string

	hostsMTime time.Time
	hostsSize  int64

	Next plugin.Handler
}

func New() *IranBanResolver {
	r, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")

	return &IranBanResolver{
		hosts:       "/etc/hosts_dir/hosts-ban",
		reload:      5 * time.Second,
		resolveFrom: r,
	}
}

// Name implements the Handler interface.
func (ibr *IranBanResolver) Name() string { return "iran_ban_resolver" }

// ServeDNS implements the plugin.Handler interface. This method gets called when iran_resolver is used
// in a Server.
func (ibr *IranBanResolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	state := request.Request{W: w, Req: r}
	qname := state.Name()

	// is qname in ban list
	if strings.Contains(ibr.hosts, strings.TrimSuffix(qname, ".")) {
		fmt.Printf("[IBR-INFO] {%s} is in banned list, resolve it from %s\n", qname, ibr.resolveFrom.String())

		answers := []dns.RR{}

		switch state.QType() {
		//case dns.TypePTR:
		case dns.TypeA:
			resp, err := dns.Exchange(state.Req, ibr.resolveFrom.String())

			if err != nil {
				fmt.Printf("[IBR-ERROR] {%s} is in banned list, resolve it from %s\n", qname, ibr.resolveFrom.String())
				return plugin.NextOrFailure(ibr.Name(), ibr.Next, ctx, w, r)
			}

			answers = resp.Answer
		case dns.TypeAAAA:
			resp, err := dns.Exchange(state.Req, ibr.resolveFrom.String())

			if err != nil {
				fmt.Printf("[IBR-ERROR] {%s} is in banned list, resolve it from %s\n", qname, ibr.resolveFrom.String())
				return plugin.NextOrFailure(ibr.Name(), ibr.Next, ctx, w, r)
			}

			answers = resp.Answer
		default:
			return plugin.NextOrFailure(ibr.Name(), ibr.Next, ctx, w, r)
		}

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answers

		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(ibr.Name(), ibr.Next, ctx, w, r)

}

// readHosts determines if the cached data needs to be updated based on and modification time of the hostsfile.
func (ibr *IranBanResolver) readHosts() {
	file, err := os.Open(ibr.hostsPath)
	if err != nil {
		// We already log a warning if the file doesn't exist or can't be opened on setup. No need to return the error here.
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return
	}
	ibr.RLock()
	size := ibr.hostsSize
	ibr.RUnlock()

	if ibr.hostsMTime.Equal(stat.ModTime()) && size == stat.Size() {
		return
	}

	ibr.Lock()

	var content string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}

	ibr.hosts = content

	// Update the data cache.
	ibr.hostsMTime = stat.ModTime()
	ibr.hostsSize = stat.Size()

	ibr.Unlock()
}
