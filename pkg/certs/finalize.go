package certs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// orderLocations works around a gap between Go's ACME client and RFC 8555.
//
// After finalizing an order the client waits for it at the address in the
// finalize response's Location header. RFC 8555 doesn't require that header,
// and some ACME servers leave it out when the certificate isn't ready yet; the
// client then posts to an empty address and the certificate is never fetched.
// This transport remembers each order's address (from the response that
// created or fetched it) and fills in Location on a finalize response that
// lacks it. Responses that already have it are untouched.
type orderLocations struct {
	rt http.RoundTripper

	mu     sync.Mutex
	orders map[string]string // finalize URL -> order URL
}

func newOrderLocations(rt http.RoundTripper) *orderLocations {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &orderLocations{rt: rt, orders: map[string]string{}}
}

// acmeHTTPClient wraps base (which may be nil) with the workaround.
func acmeHTTPClient(base *http.Client) *http.Client {
	c := &http.Client{Timeout: time.Minute}
	if base != nil {
		c.Timeout = base.Timeout
		c.Transport = newOrderLocations(base.Transport)
	} else {
		c.Transport = newOrderLocations(nil)
	}
	return c
}

func (o *orderLocations) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := o.rt.RoundTrip(r)
	if err != nil || r.Method != http.MethodPost {
		return resp, err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if rerr != nil {
		return resp, nil
	}
	var order struct {
		Finalize string `json:"finalize"`
	}
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || json.Unmarshal(body, &order) != nil || order.Finalize == "" {
		return resp, nil // not an order
	}
	reqURL := r.URL.String()
	o.mu.Lock()
	defer o.mu.Unlock()
	switch loc := resp.Header.Get("Location"); {
	case reqURL == order.Finalize:
		// The finalize response: give it the order's address if it lacks one.
		if loc == "" {
			if known, ok := o.orders[order.Finalize]; ok {
				resp.Header.Set("Location", known)
			}
		}
	case loc != "":
		o.orders[order.Finalize] = loc // a new order: its address is in Location
	default:
		o.orders[order.Finalize] = reqURL // fetching an order: this is its address
	}
	return resp, nil
}
