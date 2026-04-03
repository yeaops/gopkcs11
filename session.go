package gopkcs11

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// Session wraps a PKCS#11 session handle.
// All sessions share the Token's PKCS#11 context for efficiency.
type Session struct {
	ctx      *pkcs11.Ctx // shared PKCS#11 context from Token
	handle   pkcs11.SessionHandle
	lastUsed time.Time
	pool     *Pool
}

// GetCtx returns the underlying PKCS#11 context.
func (c *Session) GetCtx() *pkcs11.Ctx {
	c.lastUsed = time.Now()
	return c.ctx
}

// GetHandle returns the underlying PKCS#11 session handle.
func (c *Session) GetHandle() pkcs11.SessionHandle {
	c.lastUsed = time.Now()
	return c.handle
}

// Release returns the context back to the pool for reuse.
func (c *Session) Release() {
	c.pool.release(c)
}

// Pool manages a pool of PKCS#11 sessions for concurrent access.
// All sessions share the same PKCS#11 context from the Token.
// It provides thread-safe allocation and deallocation with configurable
// pool size limits and acquisition timeouts.
type Pool struct {
	config         *Config
	ctx            *pkcs11.Ctx // shared PKCS#11 context from Token
	sessions       chan *Session
	maxSessions    int
	acquireTimeout time.Duration
	activeCount    int64        // atomic counter for active sessions
	targetSlot     uint         // the slot to use for all sessions
	mu             sync.RWMutex // protects pool state
	closed         bool
	closeOnce      sync.Once

	createMu sync.RWMutex
}

// newPool creates a new session pool.
func newPool(config *Config, ctx *pkcs11.Ctx, targetSlot uint) (*Pool, error) {
	// Set default values if not configured
	maxSessions := config.MaxSessions
	if maxSessions == 0 {
		maxSessions = 1024 // default
	}

	pool := &Pool{
		config:         config,
		ctx:            ctx,
		sessions:       make(chan *Session, maxSessions),
		maxSessions:    maxSessions,
		acquireTimeout: config.SessionAcquireTimeout,
		targetSlot:     targetSlot,
		activeCount:    0,
		closed:         false,
	}

	// Create initial session to verify configuration
	initialSession, err := pool.createSession()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create initial session")
	}

	// Put the initial session into the pool
	pool.sessions <- initialSession
	atomic.AddInt64(&pool.activeCount, 1)

	return pool, nil
}

// acquire gets a context from the pool with timeout support.
func (p *Pool) acquire(ctx context.Context) (*Session, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("context pool is closed")
	}
	p.mu.RUnlock()

	// Create timeout context if configured
	var timeoutCtx context.Context
	var cancel context.CancelFunc
	if p.acquireTimeout > 0 {
		timeoutCtx, cancel = context.WithTimeout(ctx, p.acquireTimeout)
		defer cancel()
	} else {
		timeoutCtx = ctx
	}

	select {
	case session := <-p.sessions:
		// Validate context health
		if p.validateSession(session) {
			session.lastUsed = time.Now()
			return session, nil
		}
		// Session is invalid, try to create a new one
		atomic.AddInt64(&p.activeCount, -1)
		return p.createSessionIfCapacity()

	default:
		// Pool is empty, try to create new context if under capacity
		return p.acquireOrWait(timeoutCtx)
	}
}

// acquireOrWait tries to create a new context or waits for an available one.
func (p *Pool) acquireOrWait(ctx context.Context) (*Session, error) {
	// Try to create new context if under capacity
	if session, err := p.createSessionIfCapacity(); err == nil {
		return session, nil
	}

	// At capacity, wait for available context
	select {
	case session := <-p.sessions:
		if p.validateSession(session) {
			session.lastUsed = time.Now()
			return session, nil
		}
		// session is invalid, try again
		atomic.AddInt64(&p.activeCount, -1)
		return p.acquireOrWait(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// createSessionIfCapacity creates a new context if under capacity.
func (p *Pool) createSessionIfCapacity() (*Session, error) {
	currentCount := atomic.LoadInt64(&p.activeCount)
	if currentCount >= int64(p.maxSessions) {
		return nil, errors.New("context pool at capacity")
	}

	session, err := p.createSession()
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&p.activeCount, 1)
	session.lastUsed = time.Now()
	return session, nil
}

// release returns a context to the pool.
func (p *Pool) release(session *Session) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		// Pool is closed, clean up the session
		p.closeSession(session)
		return
	}

	// Validate session before returning to pool
	if !p.validateSession(session) {
		// Session is invalid, close it and don't return to pool
		p.closeSession(session)
		atomic.AddInt64(&p.activeCount, -1)
		return
	}

	// Return to pool (non-blocking)
	select {
	case p.sessions <- session:
		// Successfully returned to pool
	default:
		// Pool is full, close this context
		p.closeSession(session)
		atomic.AddInt64(&p.activeCount, -1)
	}
}

// createSession creates a new PKCS#11 session using the shared context.
func (p *Pool) createSession() (*Session, error) {
	p.createMu.Lock()
	defer p.createMu.Unlock()
	// Create session on the shared context
	p11Session, err := p.ctx.OpenSession(p.targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open session")
	}

	return &Session{
		ctx:      p.ctx, // reference to shared context
		handle:   p11Session,
		lastUsed: time.Now(),
		pool:     p,
	}, nil
}

// validateSession checks if a context is still valid.
func (p *Pool) validateSession(session *Session) bool {
	if session == nil || session.ctx == nil {
		return false
	}

	// Test the session by getting session info
	_, err := session.ctx.GetSessionInfo(session.handle)
	return err == nil
}

// closeSession properly closes a session, logs out, but does not destroy the shared context.
func (p *Pool) closeSession(session *Session) {
	if session != nil && session.ctx != nil && session.handle != 0 {
		session.ctx.CloseSession(session.handle)
	}
}

// close shuts down the context pool and cleans up all sessions.
func (p *Pool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.sessions)

	// Clean up all remaining sessions
	for session := range p.sessions {
		p.closeSession(session)
	}

	return nil
}
