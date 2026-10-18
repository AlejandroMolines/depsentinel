package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fast(offline bool) *Client {
	c := New(2*time.Second, offline)
	c.Backoff = time.Millisecond
	return c
}

func TestRetriesOn5xxThenSucceeds(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	var out struct{ OK bool }
	if err := fast(false).GetJSON(context.Background(), srv.URL, nil, &out); err != nil || !out.OK || n != 3 {
		t.Errorf("reintentos: n=%d out=%+v err=%v", n, out, err)
	}
}

func TestNotFoundIsNotRetried(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	err := fast(false).GetJSON(context.Background(), srv.URL, nil, &struct{}{})
	if !IsNotFound(err) || n != 1 {
		t.Errorf("404: err=%v n=%d", err, n)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 {
		t.Errorf("debe ser *StatusError: %v", err)
	}
}

func TestOfflineNeverTouchesTheNetwork(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&n, 1) }))
	defer srv.Close()
	if _, err := fast(true).GetBytes(context.Background(), srv.URL, nil); !errors.Is(err, ErrOffline) || n != 0 {
		t.Errorf("offline: %v n=%d", err, n)
	}
}

func TestContextCancelAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" || r.Header.Get("X-Test") != "1" {
			http.Error(w, "cabeceras", http.StatusBadRequest)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := fast(false).GetBytes(ctx, srv.URL, map[string]string{"X-Test": "1"}); err == nil {
		t.Error("el contexto cancelado debe devolver error")
	}
}
