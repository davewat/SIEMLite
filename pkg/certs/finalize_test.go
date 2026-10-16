package certs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A server that, like some ACME CAs, finalizes without a Location header.
func TestFinalizeGetsTheOrderLocation(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	order := func(w http.ResponseWriter, status string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": status, "finalize": srvURL + "/finalize/1"})
	}
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srvURL+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"status": "pending", "finalize": srvURL + "/finalize/1"})
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) { order(w, "processing") }) // no Location
	mux.HandleFunc("/finalize/2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srvURL+"/elsewhere")
		order(w, "processing")
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"valid"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	c := acmeHTTPClient(nil)
	post := func(path string) *http.Response {
		resp, err := c.Post(srv.URL+path, "application/jose+json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	post("/new-order")
	if got := post("/finalize/1").Header.Get("Location"); got != srv.URL+"/order/1" {
		t.Errorf("finalize Location = %q, want the order's address", got)
	}
	// A Location the server did send is never changed.
	if got := post("/finalize/2").Header.Get("Location"); got != srv.URL+"/elsewhere" {
		t.Errorf("an existing Location was changed to %q", got)
	}
	// Bodies still arrive intact, and non-orders are untouched.
	resp, _ := c.Post(srv.URL+"/other", "application/jose+json", strings.NewReader("{}"))
	var v map[string]string
	json.NewDecoder(resp.Body).Decode(&v)
	resp.Body.Close()
	if v["status"] != "valid" || resp.Header.Get("Location") != "" {
		t.Errorf("non-order response changed: %v %q", v, resp.Header.Get("Location"))
	}
}

// Fetching an order (POST-as-GET to its address) also teaches its address.
func TestOrderFetchTeachesTheLocation(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/order/7", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ready", "finalize": srvURL + "/finalize/7"})
	})
	mux.HandleFunc("/finalize/7", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "processing", "finalize": srvURL + "/finalize/7"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	c := acmeHTTPClient(&http.Client{})
	for _, p := range []string{"/order/7", "/finalize/7"} {
		resp, err := c.Post(srv.URL+p, "application/jose+json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if p == "/finalize/7" && resp.Header.Get("Location") != srv.URL+"/order/7" {
			t.Errorf("Location = %q", resp.Header.Get("Location"))
		}
	}
}
