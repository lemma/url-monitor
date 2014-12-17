package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/benburkert/lemma-monitor/Godeps/_workspace/src/code.google.com/p/go.net/context"
	"github.com/benburkert/lemma-monitor/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/benburkert/lemma-monitor/Godeps/_workspace/src/github.com/stvp/pager"
)

var (
	dnsServers = []string{}

	pdToken  = os.Getenv("PAGERDUTY_TOKEN")
	pdClient *pager.Pager
)

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	pdClient = pager.New(pdToken)
	dnsConf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	for _, s := range dnsConf.Servers {
		dnsServers = append(dnsServers, net.JoinHostPort(s, dnsConf.Port))
	}

	pctx := context.Background()
	t := time.NewTicker(30 * time.Second)

	incidents := map[string]string{}
	urls := []*url.URL{}
	for _, s := range os.Args[1:] {
		u, err := url.Parse(s)
		if err != nil {
			fatal(err)
		}
		urls = append(urls, u)
	}

	type urs struct {
		u  *url.URL
		rs results
	}
	ch := make(chan urs)

	for {
		ctx, _ := context.WithTimeout(pctx, 10*time.Second)
		for _, u := range urls {
			go func(u *url.URL) {
				ch <- urs{u, monitor(ctx, u)}
			}(u)
		}

		for range urls {
			urs := <-ch
			u, rs := urs.u, urs.rs

			if rs.IsSuccess() {
				delete(incidents, u.String())
			} else {
				incident, err := alert(u, rs, incidents[u.String()])
				if err != nil {
					fatal(err)
				}
				incidents[u.String()] = incident
			}
		}

		<-t.C
	}
}

func alert(u *url.URL, rs results, incident string) (string, error) {
	description := fmt.Sprintf("FAILURE for %s monitor", u)
	details := map[string]interface{}{}
	for k, err := range rs {
		if err != nil {
			details[k] = err.Error()
		}
	}

	if incident == "" {
		return pdClient.TriggerWithDetails(description, details)
	}
	return pdClient.TriggerIncidentKeyWithDetails(description, incident, details)
}

func monitor(ctx context.Context, u *url.URL) results {
	rctx, _ := context.WithTimeout(ctx, 5*time.Second)
	ips, err := resolve(rctx, u.Host)
	if err != nil {
		return results{u.String(): err}
	}

	wg := sync.WaitGroup{}
	rs := results{}
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			cctx, _ := context.WithTimeout(ctx, 5*time.Second)
			rs[ip] = check(cctx, u, ip)
			wg.Done()
		}(ip)
	}

	wg.Wait()
	return rs
}

func resolve(ctx context.Context, host string) ([]string, error) {
	type ipsErr struct {
		ips []string
		err error
	}

	ch := make(chan ipsErr)
	go func() {
		ips, err := doResolve(host)
		ch <- ipsErr{ips, err}
	}()

	select {
	case ie := <-ch:
		return ie.ips, ie.err
	case <-ctx.Done():
		return nil, errors.New("DNS query timeout")
	}
}

func doResolve(host string) ([]string, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)

	server := dnsServers[rand.Intn(len(dnsServers))]
	r, err := dns.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, errors.New("invalid DNS answer")
	}

	ips := []string{}
	for _, rr := range r.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			return nil, errors.New("invalid DNS answer")
		}

		ips = append(ips, a.A.String())
	}

	if len(ips) == 0 {
		return nil, errors.New("missing DNS records")
	}

	return ips, nil
}

func check(ctx context.Context, u *url.URL, ip string) error {
	ch := make(chan error)

	go func() {
		ch <- doCheck(u, ip)
	}()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return errors.New("http request timeout")
	}
}

func doCheck(u *url.URL, ip string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: u.Host,
		},
		Dial: func(_, _ string) (net.Conn, error) {
			switch u.Scheme {
			case "https":
				return net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 2*time.Second)
			case "http":
				return net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), 2*time.Second)
			default:
				return nil, errors.New("invalid scheme for " + u.String())
			}
		},
	}

	client := http.Client{Transport: tr}
	response, err := client.Get(u.String())
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return errors.New("expected 200 OK, got " + response.Status)
	}
	return nil
}

type results map[string]error

func (rs results) IsSuccess() bool {
	for _, err := range rs {
		if err != nil {
			return false
		}
	}
	return true
}

func fatal(err error) { log.Fatal(err) }

func help() {}
