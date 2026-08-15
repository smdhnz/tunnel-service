package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVercelExactRecordConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing auth")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"records":[{"name":"foo"},{"name":"*.example.com"},{"name":"other.example.com"}],"pagination":{"next":null}}`))
	}))
	defer srv.Close()
	v := &VercelDNS{Token: "token", Domain: "example.com", BaseURL: srv.URL}
	yes, err := v.HasExactRecord(context.Background(), "foo")
	if err != nil || !yes {
		t.Fatalf("exact not found: %v", err)
	}
	yes, err = v.HasExactRecord(context.Background(), "wild")
	if err != nil || yes {
		t.Fatalf("wildcard treated as conflict: %v %v", yes, err)
	}
}
func TestVercelPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("until") == "42" {
			w.Write([]byte(`{"records":[{"name":"later"}],"pagination":{"next":null}}`))
			return
		}
		w.Write([]byte(`{"records":[],"pagination":{"next":42}}`))
	}))
	defer srv.Close()
	v := &VercelDNS{Token: "token", Domain: "example.com", BaseURL: srv.URL}
	yes, err := v.HasExactRecord(context.Background(), "later")
	if err != nil || !yes {
		t.Fatalf("paginated exact record not found: %v", err)
	}
}

func TestVercelInvalidPaginationFailsClosed(t *testing.T) {
	for name, response := range map[string]string{
		"missing":  `{"records":[]}`,
		"repeated": `{"records":[],"pagination":{"next":"same"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(response))
			}))
			defer srv.Close()
			v := &VercelDNS{Token: "token", Domain: "example.com", BaseURL: srv.URL}
			if _, err := v.HasExactRecord(context.Background(), "absent"); err == nil {
				t.Fatal("invalid pagination was treated as complete")
			}
			if name == "repeated" && requests < 2 {
				t.Fatalf("repeat path not exercised: %d requests", requests)
			}
		})
	}
}

func TestVercelAPIErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusServiceUnavailable) }))
	defer srv.Close()
	v := &VercelDNS{Token: "token", Domain: "example.com", BaseURL: srv.URL}
	if _, err := v.HasExactRecord(context.Background(), "foo"); err == nil {
		t.Fatal("API error ignored")
	}
	v.Token = ""
	if _, err := v.HasExactRecord(context.Background(), "foo"); err == nil {
		t.Fatal("missing token ignored")
	}
}
