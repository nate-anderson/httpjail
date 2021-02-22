package httpjail

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Jail monitors requests and jails violating IPs
type Jail struct {
	// is the server running behind a proxy or load balancer?
	isProxied bool
	// number of requests to allow
	AllowedRequests int
	// duration to consider request coutn
	Window time.Duration
	// should jailed clients recieve no response?
	NoRespond bool
	visitors  VisitorLog
	// duration to prevent requests after limit is reached
	Cooloff   time.Duration
	Sentences map[string]time.Time
}

// VisitorLog defines visitor request logging/log reading
type VisitorLog interface {
	LogVisit(req *http.Request)
	CountVisits(req *http.Request, since time.Time) int
}

// IsProxied sets the jail to proxy mode, using the X-Forwarded-For header instead of the request IP
func (j *Jail) IsProxied() {
	j.isProxied = true
}

// Middleware returns the jail's HTTP middleware
func (j Jail) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// rewrite RemoteAddr if proxied
		if j.isProxied {
			req.RemoteAddr = req.Header.Get("X-Forwarded-For")
		}

		j.visitors.LogVisit(req)

		if !j.isSentenced(req) {
			since := time.Now().Add(-j.Window)
			reqCount := j.visitors.CountVisits(req, since)
			if reqCount <= j.AllowedRequests {
				next.ServeHTTP(w, req)
				return
			}
		}

		j.sentence(req)

		if !j.NoRespond {
			fmt.Fprint(w, "You are doing that too much. Please slow down and try again later.")
			return
		}
	})
}

// isSentenced checks if the address is subject to a cooloff period
func (j Jail) isSentenced(req *http.Request) bool {
	release, isJailed := j.Sentences[req.RemoteAddr]
	return isJailed && release.After(time.Now())
}

// sentence address to a cooloff
func (j Jail) sentence(req *http.Request) {
	sentence := time.Now().Add(j.Cooloff)
	j.Sentences[req.RemoteAddr] = sentence
}

const cleanupEvery = 100

// DefaultVisitorLog is the default implementation of VisitorLog
type DefaultVisitorLog struct {
	visits map[string][]time.Time
}

var logVisitMux = sync.Mutex{}

// NewDefaultVisitorLog instantiates a DefaultVisitorLog
func NewDefaultVisitorLog() *DefaultVisitorLog {
	return &DefaultVisitorLog{
		visits: make(map[string][]time.Time),
	}
}

// LogVisit logs an IP address request
func (l *DefaultVisitorLog) LogVisit(req *http.Request) {
	logVisitMux.Lock()
	l.visits[req.RemoteAddr] = append(l.visits[req.RemoteAddr], time.Now())
	logVisitMux.Unlock()
}

// CountVisits counts the visitor's visit
func (l *DefaultVisitorLog) CountVisits(req *http.Request, since time.Time) int {
	var visits []time.Time
	for _, visit := range l.visits[req.RemoteAddr] {
		if visit.After(since) || visit.Equal(since) {
			visits = append(visits, visit)
		}
	}

	// remove old visits
	l.visits[req.RemoteAddr] = visits
	return len(visits)
}

// NewJail constructs a new Jail
func NewJail(visitorLog VisitorLog, window, cooloff time.Duration, allowedRequests int) *Jail {
	return &Jail{
		AllowedRequests: allowedRequests,
		Window:          window,
		Cooloff:         cooloff,
		visitors:        visitorLog,
		Sentences:       make(map[string]time.Time),
	}
}

// NewBasicJail creates a new jail with a second-duration window and a default visitor log
func NewBasicJail(windowSeconds int64, allowedRequests int, noRespond bool) *Jail {
	log := NewDefaultVisitorLog()
	window, _ := time.ParseDuration(fmt.Sprintf("%ds", windowSeconds))
	return &Jail{
		AllowedRequests: allowedRequests,
		visitors:        log,
		Window:          window,
		NoRespond:       noRespond,
		Sentences:       make(map[string]time.Time),
	}
}
