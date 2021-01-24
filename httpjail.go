package httpjail

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Jail monitors requests and jails violating IPs
type Jail struct {
	// number of requests to allow
	AllowedRequests int
	// duration to consider request coutn
	Window time.Duration
	// should jailed clients recieve no response?
	NoRespond bool
	visitors  VisitorLog
}

// VisitorLog defines visitor request logging/log reading
type VisitorLog interface {
	LogVisit(ipAddr string)
	CountVisits(ipAddr string, since time.Time) int
}

// Middleware returns the jail's HTTP middleware
func (j Jail) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ipAddr := req.RemoteAddr
		j.visitors.LogVisit(ipAddr)

		since := time.Now().Add(-j.Window)
		reqCount := j.visitors.CountVisits(ipAddr, since)
		if reqCount < j.AllowedRequests {
			next.ServeHTTP(w, req)
			return
		}

		if !j.NoRespond {
			fmt.Fprint(w, "You are doing that too much. Please slow down and try again later.")
			return
		}
	})
}

const cleanupEvery = 100

// defaultVisitorLog is the default implementation of VisitorLog
type defaultVisitorLog struct {
	visits map[string][]time.Time
}

var logVisitMux = sync.Mutex{}

// LogVisit logs an IP address request
func (l *defaultVisitorLog) LogVisit(ipAddr string) {
	logVisitMux.Lock()
	l.visits[ipAddr] = append(l.visits[ipAddr], time.Now())
	logVisitMux.Unlock()
}

// CountVisits counts the visitor's
func (l defaultVisitorLog) CountVisits(ipAddr string, since time.Time) int {
	var count int
	for _, visit := range l.visits[ipAddr] {
		if visit.After(since) {
			count++
		}
	}

	return count
}

// NewJail constructs a new Jail
func NewJail(visitorLog VisitorLog, window time.Duration, allowedRequests int) *Jail {
	return &Jail{
		AllowedRequests: allowedRequests,
		Window:          window,
		visitors:        visitorLog,
	}
}

// NewBasicJail creates a new jail with a second-duration window and a default visitor log
func NewBasicJail(windowSeconds int64, allowedRequests int, noRespond bool) *Jail {
	log := defaultVisitorLog{
		visits: make(map[string][]time.Time),
	}
	window, _ := time.ParseDuration(fmt.Sprintf("%ds", windowSeconds))
	return &Jail{
		AllowedRequests: allowedRequests,
		visitors:        &log,
		Window:          window,
		NoRespond:       noRespond,
	}
}
