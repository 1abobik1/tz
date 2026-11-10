package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// State результат подключения или DNS-запроса
type State string

const (
	Open        State = "open"
	Closed      State = "closed"
	Timeout     State = "timeout"
	Unreachable State = "unreachable"
	Canceled    State = "canceled"
	Error       State = "error"
)

// Result содержит результат проверки. При ошибке DNS поле IP равно nil
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

// Option задаёт настройки сканера
type Option func(*config) error

type config struct {
	concurrency int
	timeout     time.Duration
}

// WithConcurrency задаёт общий лимит подключений сканера
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("portscan: concurrency must be positive")
		}
		c.concurrency = n
	
		return nil
	}
}

// WithConnectTimeout задаёт таймаут подключения и DNS-запроса
func WithConnectTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout <= 0 {
			return fmt.Errorf("portscan: timeout must be positive")
		}
		c.timeout = timeout
	
		return nil
	}
}

// Scanner безопасен для конкурентного использования; создаётся через New
type Scanner struct {
	config config
	slots  chan struct{}
	dial   func(context.Context, string, string) (net.Conn, error)
	lookup func(context.Context, string) ([]net.IPAddr, error)
}

// New создаёт сканер с лимитом 100 подключений и таймаутом 500 мс
func New(options ...Option) (*Scanner, error) {
	c := config{concurrency: 100, timeout: 500 * time.Millisecond}
	
	for _, option := range options {
		if option == nil {
			return nil, errors.New("portscan: nil option")
		}
	
		if err := option(&c); err != nil {
			return nil, err
		}
	}
	
	return &Scanner{
		config: c,
		slots:  make(chan struct{}, c.concurrency),
		dial:   (&net.Dialer{}).DialContext,
		lookup: net.DefaultResolver.LookupIPAddr,
	}, nil
}

type job struct {
	host          string
	ip            net.IP
	port          uint16
	resolutionErr error
	duration      time.Duration
}

// Scan проверяет параметры и возвращает канал результатов
// При досрочном прекращении чтения необходимо отменить ctx
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if s == nil || s.slots == nil {
		return nil, errors.New("portscan: scanner must be constructed with New")
	}
	
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	
	if ports.err != nil {
		return nil, ports.err
	}
	
	if len(ports.values) == 0 {
		return nil, errors.New("portscan: empty ports")
	}
	
	if len(hosts) == 0 {
		return nil, errors.New("portscan: empty hosts")
	}
	
	targets := make([]string, 0, len(hosts))
	seenHosts := make(map[string]bool)
	
	for _, host := range hosts {
		h, err := normalizeHost(host)
	
		if err != nil {
			return nil, err
		}
	
		if !seenHosts[h] {
			seenHosts[h] = true
			targets = append(targets, h)
		}
	}
	
	selected := make([]uint16, 0, len(ports.values))
	var seenPorts [65536]bool
	
	for _, p := range ports.values {
		if !seenPorts[p] {
			seenPorts[p] = true
			selected = append(selected, p)
		}
	}
	
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	
	jobs := make(chan job)
	out := make(chan Result, s.config.concurrency)
	
	go s.produce(ctx, targets, selected, jobs)

	var wg sync.WaitGroup
	for i := 0; i < s.config.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.work(ctx, jobs, out)
		}()
	}
	
	go func() {
		wg.Wait()
		close(out)
	}()
	
	return out, nil
}

func (s *Scanner) produce(ctx context.Context, targets []string, selected []uint16, jobs chan<- job) {
	defer close(jobs)
	for _, host := range targets {
		if ctx.Err() != nil {
			return
		}
		
		start := time.Now()
		var addresses []net.IPAddr
		var err error
		
		if ip := net.ParseIP(host); ip != nil {
			addresses = []net.IPAddr{{IP: ip}}
		} else {
			lookupCtx, cancel := context.WithTimeout(ctx, s.config.timeout)
			addresses, err = s.lookup(lookupCtx, host)
			cancel()
		
			if err == nil && len(addresses) == 0 {
				err = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
			}
		}
		
		elapsed := time.Since(start)
		if err != nil {
			addresses = []net.IPAddr{{}}
		}
		
		seen := make(map[string]bool)
		for _, address := range addresses {
			key := address.IP.String()
			
			if seen[key] {
				continue
			}

			seen[key] = true
			
			for _, port := range selected {
				if ctx.Err() != nil {
					return
				}
			
				select {
				case jobs <- job{host, address.IP, port, err, elapsed}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Scanner) work(ctx context.Context, jobs <-chan job, out chan<- Result) {
	for j := range jobs {
		if ctx.Err() != nil {
			return
		}
		r, ok := s.check(ctx, j)
		if !ok {
			return
		}

		// Сохраняем результат, если в канале есть место
		select {
		case out <- r:
			continue
		default:
		}
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}

// check возвращает false, если задание отменено до подключения
func (s *Scanner) check(ctx context.Context, j job) (Result, bool) {
	result := Result{Host: j.host, IP: append(net.IP(nil), j.ip...), Port: j.port}

	if j.resolutionErr != nil {
		result.Err = j.resolutionErr
		result.Duration = j.duration
		result.State = classify(result.Err)

		return result, true
	}

	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return Result{}, false
	}
	defer func() { <-s.slots }()
	if ctx.Err() != nil {
		return Result{}, false
	}

	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, s.config.timeout)
	defer cancel()

	address := net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port)))
	conn, err := s.dial(dialCtx, "tcp", address)

	if conn != nil {
		_ = conn.Close()
	}

	result.Duration = time.Since(start)
	result.Err = err
	result.State = classify(err)

	return result, true
}
