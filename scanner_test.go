package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func collect(t *testing.T, ch <-chan Result) []Result {
	t.Helper()
	var results []Result
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, r)

		case <-timer.C:
			t.Fatal("scan did not finish")
			return nil
		}
	}
}

func TestPortsAndValidation(t *testing.T) {
	s, _ := New()
	for _, p := range []Ports{List(0), List(65536), List(-1), Range(10, 1), Range(0, 2), Range(1, 65536), {}, Union(List(1), List(0))} {
		if _, err := s.Scan(context.Background(), []string{"localhost"}, p); err == nil {
			t.Errorf("accepted invalid ports: %+v", p)
		}
	}

	for _, h := range []string{"", " ", "999.1.1.1", "a:80", "[::1]", "a..b", "-bad", "bad_thing", "fe80::1%eth0"} {
		if _, err := s.Scan(context.Background(), []string{h}, List(80)); err == nil {
			t.Errorf("accepted host %q", h)
		}
	}

	for _, opt := range []Option{nil, WithConcurrency(0), WithConcurrency(-1), WithConnectTimeout(0), WithConnectTimeout(-time.Second)} {
		if _, err := New(opt); err == nil {
			t.Error("accepted invalid option")
		}
	}

	if _, err := s.Scan(nil, []string{"localhost"}, List(80)); err == nil {
		t.Error("nil context")
	}

	if _, err := s.Scan(context.Background(), nil, List(80)); err == nil {
		t.Error("empty hosts")
	}

	var zero Scanner
	if _, err := zero.Scan(context.Background(), []string{"localhost"}, List(80)); err == nil {
		t.Error("zero scanner")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Scan(ctx, []string{"localhost"}, List(80)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err   error
		state State
	}{
		{nil, Open}, {context.Canceled, Canceled}, {context.DeadlineExceeded, Timeout},
		{syscall.ECONNREFUSED, Closed}, {syscall.ENETUNREACH, Unreachable}, {syscall.EHOSTUNREACH, Unreachable},
		{syscall.ENETDOWN, Unreachable}, {syscall.EHOSTDOWN, Unreachable}, {syscall.ETIMEDOUT, Timeout},
		{&net.DNSError{IsNotFound: true}, Unreachable}, {&net.DNSError{IsTimeout: true}, Timeout},
		{errors.New("connection refused"), Error},
	}

	for _, tt := range cases {
		err := tt.err
		if err != nil {
			err = fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: err})
		}

		if got := classify(err); got != tt.state {
			t.Errorf("%v: got %s want %s", err, got, tt.state)
		}
	}
}

func TestRealTCP(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "tcp6" {
				host = "::1"
			}

			listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
			if err != nil {
				if network == "tcp6" {
					t.Skip(err)
				}
				t.Fatal(err)
			}

			defer listener.Close()
			accepted := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					accepted <- err
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				var b [1]byte
				_, err = c.Read(b[:])
				accepted <- err
			}()

			port := listener.Addr().(*net.TCPAddr).Port
			s, _ := New()
			ch, err := s.Scan(context.Background(), []string{host}, List(port))

			if err != nil {
				t.Fatal(err)
			}

			rs := collect(t, ch)
			if len(rs) != 1 || rs[0].State != Open || rs[0].Err != nil || !rs[0].IP.Equal(net.ParseIP(host)) {
				t.Fatalf("%+v", rs)
			}

			select {
			case err := <-accepted:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("expected EOF, got %v", err)
				}

				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Fatal("connection was not closed")
				}

			case <-time.After(4 * time.Second):
				t.Fatal("connection was not closed")
			}

			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}

			ch, err = s.Scan(context.Background(), []string{host}, List(port))
			if err != nil {
				t.Fatal(err)
			}

			rs = collect(t, ch)
			if len(rs) != 1 || rs[0].State != Closed {
				t.Fatalf("%+v", rs)
			}
		})
	}
}

func TestDNSAndDeduplication(t *testing.T) {
	s, _ := New(WithConcurrency(3))
	var lookups atomic.Int32

	s.lookup = func(ctx context.Context, h string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}

	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	p := Union(Range(80, 81), List(81, 82))
	ch, err := s.Scan(context.Background(), []string{" EXAMPLE.com ", "example.com.", "EXAMPLE.COM"}, p)

	if err != nil {
		t.Fatal(err)
	}

	rs := collect(t, ch)
	if len(rs) != 6 || lookups.Load() != 1 {
		t.Fatalf("results=%d lookups=%d", len(rs), lookups.Load())
	}

	seen := map[string]bool{}
	for _, r := range rs {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if seen[key] || r.Host != "example.com" || r.State != Closed {
			t.Fatalf("%+v", r)
		}

		seen[key] = true
	}

	s.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Name: "missing.test", IsNotFound: true}
	}

	ch, err = s.Scan(context.Background(), []string{"missing.test"}, p)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range collect(t, ch) {
		if r.IP != nil || r.State != Unreachable || r.Err == nil {
			t.Fatalf("%+v", r)
		}
	}

	s.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }
	ch, _ = s.Scan(context.Background(), []string{"empty.test"}, List(80))

	if rs = collect(t, ch); len(rs) != 1 || rs[0].State != Unreachable {
		t.Fatalf("%+v", rs)
	}
}

func TestConcurrentReuseAndLimit(t *testing.T) {
	s, _ := New(WithConcurrency(3))
	var active, peak, calls atomic.Int32

	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)

		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}

		select {
		case <-time.After(time.Millisecond):
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, Range(1, 20))

			if err != nil {
				t.Error(err)
				return
			}

			var n int
			for range ch {
				n++
			}

			if n != 20 {
				t.Errorf("results %d", n)
			}
		}()
	}

	wg.Wait()

	if peak.Load() > 3 || peak.Load() < 2 || calls.Load() != 80 || active.Load() != 0 {
		t.Fatalf("peak=%d calls=%d active=%d", peak.Load(), calls.Load(), active.Load())
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	s, _ := New(WithConcurrency(2), WithConnectTimeout(20*time.Millisecond))
	var active atomic.Int32
	started := make(chan struct{}, 2)

	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ch, _ := s.Scan(context.Background(), []string{"127.0.0.1"}, List(1))
	rs := collect(t, ch)

	if len(rs) != 1 || rs[0].State != Timeout {
		t.Fatalf("%+v", rs)
	}

	<-started
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ = s.Scan(ctx, []string{"127.0.0.1"}, Range(1, 65535))
	<-started
	<-started
	cancel()

	rs = collect(t, ch)
	if len(rs) != 2 || active.Load() != 0 {
		t.Fatalf("results %d active %d", len(rs), active.Load())
	}

	for _, r := range rs {
		if r.State != Canceled {
			t.Fatalf("%+v", r)
		}
	}
}

func TestAbandonedConsumer(t *testing.T) {
	s, _ := New(WithConcurrency(2))
	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := s.Scan(ctx, []string{"127.0.0.1"}, Range(1, 65535))

	// Даём буферу заполниться до отмены
	time.Sleep(20 * time.Millisecond)
	cancel()
	collect(t, ch)

	ch, _ = s.Scan(context.Background(), []string{"127.0.0.1"}, List(80))
	if len(collect(t, ch)) != 1 {
		t.Fatal("reuse after cancellation failed")
	}
}

func TestCancelDNS(t *testing.T) {
	s, _ := New()
	started := make(chan struct{})

	s.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := s.Scan(ctx, []string{"example.test"}, List(80))
	<-started
	cancel()

	if rs := collect(t, ch); len(rs) != 0 {
		t.Fatalf("%+v", rs)
	}
}

func TestPortSelectionsImmutable(t *testing.T) {
	args := []int{1, 2}
	p := List(args...)
	args[0] = 3

	u := Union(p, List(3))
	_ = Union(p, List(4))

	if !reflect.DeepEqual(p.values, []uint16{1, 2}) || !reflect.DeepEqual(u.values, []uint16{1, 2, 3}) {
		t.Fatal("selections mutated")
	}
}

func TestSuccessfulDialClosesConnection(t *testing.T) {
	s, _ := New(WithConcurrency(1))
	client, server := net.Pipe()
	defer server.Close()

	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	s.dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(80))
	if err != nil {
		t.Fatal(err)
	}

	rs := collect(t, ch)
	if len(rs) != 1 || rs[0].State != Open || rs[0].Err != nil {
		t.Fatalf("%+v", rs)
	}

	var b [1]byte
	if _, err := server.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("expected closed connection, got %v", err)
	}
}

func TestDNSDeadline(t *testing.T) {
	s, _ := New(WithConnectTimeout(10 * time.Millisecond))
	s.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }
	ch, err := s.Scan(context.Background(), []string{"example.test"}, List(80, 443))

	if err != nil {
		t.Fatal(err)
	}

	rs := collect(t, ch)
	if len(rs) != 2 {
		t.Fatalf("results=%d", len(rs))
	}

	for _, r := range rs {
		if r.State != Timeout || r.IP != nil || !errors.Is(r.Err, context.DeadlineExceeded) {
			t.Fatalf("%+v", r)
		}
	}
}
