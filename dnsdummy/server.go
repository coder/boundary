package dnsdummy

import (
	"log/slog"

	"github.com/miekg/dns"
)

// DummyA is the IPv4 address returned for every A record query (arbitrary non-loopback).
const DummyA = "6.6.6.6"

// DummyAAAA is the IPv6 address returned for every AAAA record query (documentation prefix).
const DummyAAAA = "2001:db8::1"

// DefaultDummyDNSPort is the port the dummy DNS server listens on (high port to avoid CAP_NET_BIND_SERVICE).
// Traffic to port 53 is DNAT'd to this port in the namespace.
const DefaultDummyDNSPort = "5353"

// Server is a minimal DNS server that responds to every query with a dummy A record.
// Used inside the network namespace to prevent DNS exfiltration.
type Server struct {
	udp    *dns.Server
	tcp    *dns.Server
	logger *slog.Logger
}

// NewServer creates a dummy DNS server that listens on addr (e.g. "127.0.0.1:53").
func NewServer(addr string, logger *slog.Logger) *Server {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				rr, err := dns.NewRR(q.Name + " 1 IN A " + DummyA)
				if err != nil {
					continue
				}
				m.Answer = append(m.Answer, rr)
			case dns.TypeAAAA:
				rr, err := dns.NewRR(q.Name + " 1 IN AAAA " + DummyAAAA)
				if err != nil {
					continue
				}
				m.Answer = append(m.Answer, rr)
			default:
				m.Rcode = dns.RcodeSuccess
			}
		}

		if err := w.WriteMsg(m); err != nil {
			logger.Debug("dummy DNS: failed to write response", "error", err)
		}
	})

	udp := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}
	tcp := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
	}

	return &Server{udp: udp, tcp: tcp, logger: logger}
}

// ListenAndServe starts the UDP and TCP servers in goroutines and returns immediately.
// Logger must be non-nil; server errors are logged via s.logger.
func (s *Server) ListenAndServe() {
	go func() {
		if err := s.tcp.ListenAndServe(); err != nil {
			s.logger.Error("dummy DNS TCP server failed", "error", err)
		}
	}()
	go func() {
		if err := s.udp.ListenAndServe(); err != nil {
			s.logger.Error("dummy DNS UDP server failed", "error", err)
		}
	}()
}

// Shutdown stops the servers.
func (s *Server) Shutdown() {
	if err := s.udp.Shutdown(); err != nil {
		s.logger.Error("dummy DNS UDP server shutdown failed", "error", err)
	}
	if err := s.tcp.Shutdown(); err != nil {
		s.logger.Error("dummy DNS TCP server shutdown failed", "error", err)
	}
}
