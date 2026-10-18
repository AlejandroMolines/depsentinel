// Package httpx es un cliente HTTP mínimo con reintentos, límite de tamaño y modo offline.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/version"
)

// ErrOffline se devuelve cuando se intenta usar la red con --offline.
var ErrOffline = errors.New("modo sin conexión (--offline)")

// StatusError representa una respuesta HTTP no exitosa.
type StatusError struct {
	Code int
	URL  string
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d en %s", e.Code, e.URL) }

// IsStatus indica si err es un StatusError con ese código.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// IsNotFound indica 404 o 410.
func IsNotFound(err error) bool { return IsStatus(err, 404) || IsStatus(err, 410) }

// Client envuelve http.Client con reintentos y User-Agent propio.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Retries   int
	Backoff   time.Duration
	Offline   bool
	MaxBody   int64
}

// New crea un cliente con el timeout indicado.
func New(timeout time.Duration, offline bool) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: timeout},
		UserAgent: version.UserAgent(),
		Retries:   2,
		Backoff:   400 * time.Millisecond,
		Offline:   offline,
		MaxBody:   64 << 20,
	}
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Do ejecuta una petición con reintentos ante errores de red, 429 y 5xx.
func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string, body []byte) ([]byte, int, error) {
	if c.Offline {
		return nil, 0, ErrOffline
	}
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(c.Backoff << (attempt - 1)):
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			lastErr = err
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &StatusError{Code: resp.StatusCode, URL: url, Body: snippet(data)}
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs <= 10 {
					select {
					case <-time.After(time.Duration(secs) * time.Second):
					case <-ctx.Done():
						return nil, 0, ctx.Err()
					}
				}
			}
			continue
		}
		return data, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

// GetBytes descarga una URL y devuelve el cuerpo si la respuesta es 2xx.
func (c *Client) GetBytes(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	data, code, err := c.Do(ctx, http.MethodGet, url, headers, nil)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		return nil, &StatusError{Code: code, URL: url, Body: snippet(data)}
	}
	return data, nil
}

// GetJSON descarga y decodifica JSON.
func (c *Client) GetJSON(ctx context.Context, url string, headers map[string]string, out any) error {
	data, err := c.GetBytes(ctx, url, headers)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("respuesta JSON inválida de %s: %w", url, err)
	}
	return nil
}

// PostJSON envía JSON y decodifica la respuesta.
func (c *Client) PostJSON(ctx context.Context, url string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	data, code, err := c.Do(ctx, http.MethodPost, url, map[string]string{"Content-Type": "application/json"}, payload)
	if err != nil {
		return err
	}
	if code < 200 || code > 299 {
		return &StatusError{Code: code, URL: url, Body: snippet(data)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("respuesta JSON inválida de %s: %w", url, err)
	}
	return nil
}
