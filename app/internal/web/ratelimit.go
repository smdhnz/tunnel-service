package web

import (
	"net/http"
	"sync"
	"time"
)

type rateEntry struct {
	tokens                float64
	updated, blockedUntil time.Time
	strikes               int
}
type rateLimiter struct {
	mu               sync.Mutex
	entries          map[string]*rateEntry
	capacity, refill float64
	block            time.Duration
	maxEntries       int
}

func newRateLimiter(capacity, perSecond float64, block time.Duration) *rateLimiter {
	return &rateLimiter{entries: map[string]*rateEntry{}, capacity: capacity, refill: perSecond, block: block, maxEntries: 10000}
}
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= l.maxEntries {
			l.evict(now)
		}
		e = &rateEntry{tokens: l.capacity, updated: now}
		l.entries[key] = e
	}
	if now.Before(e.blockedUntil) {
		return false
	}
	elapsed := now.Sub(e.updated).Seconds()
	if elapsed > 0 {
		e.tokens = min(l.capacity, e.tokens+elapsed*l.refill)
		e.updated = now
	}
	if e.tokens >= 1 {
		e.tokens--
		if e.strikes > 0 {
			e.strikes--
		}
		return true
	}
	e.strikes++
	if e.strikes >= 5 {
		e.blockedUntil = now.Add(l.block)
		e.strikes = 0
	}
	return false
}
func (l *rateLimiter) evict(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.updated) > 10*time.Minute && !now.Before(e.blockedUntil) {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.maxEntries {
		return
	}
	for k := range l.entries {
		delete(l.entries, k)
		if len(l.entries) < l.maxEntries {
			return
		}
	}
}
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lim := s.generalLimit
		if r.URL.Path == "/auth/discord" || r.URL.Path == "/auth/callback" || r.URL.Path == "/login" {
			lim = s.loginLimit
		} else if r.Method != "GET" && r.Method != "HEAD" {
			lim = s.mutationLimit
		}
		if !lim.allow(sourceIP(r), time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
