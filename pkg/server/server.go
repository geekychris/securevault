package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"securevault/pkg/audit"
	vaulterrors "securevault/pkg/errors"
	"securevault/pkg/policy"
	"securevault/pkg/seal"
	"securevault/pkg/storage"
	"securevault/pkg/ui"
)

// MaxRequestBodySize is the maximum allowed request body size (1 MB)
const MaxRequestBodySize = 1 << 20

// Config represents the server configuration
type Config struct {
	Server struct {
		Address string `yaml:"address"`
		Port    int    `yaml:"port"`
		TLS     struct {
			Enabled  bool   `yaml:"enabled"`
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
	} `yaml:"server"`

	Storage struct {
		Type string `yaml:"type"`
		Path string `yaml:"path"`
	} `yaml:"storage"`

	Auth struct {
		TokenTTL string `yaml:"token_ttl"`
	} `yaml:"auth"`

	Replication struct {
		Mode              string   `yaml:"mode"`
		ClusterAddr       string   `yaml:"cluster_addr"`
		Peers             []string `yaml:"peers"`
		SharedSecret      string   `yaml:"shared_secret"`
		LeaderAPIAddr     string   `yaml:"leader_api_addr"`      // Public API address of the leader (for forwarding)
		HealthCheckSec    int      `yaml:"health_check_sec"`     // How often followers check leader health (default: 5)
		FailoverTimeoutSec int     `yaml:"failover_timeout_sec"` // How long leader must be down before failover (default: 30)
	} `yaml:"replication"`

	Seal struct {
		SecretShares    int `yaml:"secret_shares"`
		SecretThreshold int `yaml:"secret_threshold"`
	} `yaml:"seal"`

	RateLimit struct {
		Enabled       bool    `yaml:"enabled"`
		RequestsPerSec float64 `yaml:"requests_per_sec"`
		Burst         int     `yaml:"burst"`
	} `yaml:"rate_limit"`

	Audit struct {
		Enabled bool   `yaml:"enabled"`
		Path    string `yaml:"path"`
	} `yaml:"audit"`

	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

// ReplicationEntry represents a change that needs to be replicated
type ReplicationEntry struct {
	ID        int64                  `json:"id"`
	Operation string                 `json:"op"`
	Path      string                 `json:"path"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Timestamp int64                  `json:"timestamp"`
	Version   int                    `json:"version"`
}

// Server represents the Vaultrix server
type Server struct {
	config             *Config
	storage            storage.Backend
	httpServer         *http.Server
	replicationServer  *http.Server
	policies           *policy.Manager
	sealManager        *seal.Manager
	auditLogger        audit.Logger
	tokens             map[string]TokenInfo
	tokenMutex         sync.RWMutex
	replicationLog     []ReplicationEntry
	repLogMutex        sync.RWMutex
	repLogNextID       int64
	replicationStarted bool
	replicationReady   chan struct{}
	rateLimiter        *RateLimiter
	tokenStorePath     string

	// Leader election and failover
	clusterMu      sync.RWMutex
	activeRole     string // "leader", "follower", or "standalone"
	leaderAddr     string // current known leader API address (e.g., "http://10.0.1.10:8200")
	leaderAlive    bool
	failoverCancel context.CancelFunc
}

// TokenInfo represents information about an authentication token
type TokenInfo struct {
	ID        string   `json:"id"`
	PolicyIDs []string `json:"policy_ids"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64
	lastTime time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:   float64(burst),
		max:      float64(burst),
		rate:     rate,
		lastTime: time.Now(),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now

	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.max {
		rl.tokens = rl.max
	}

	if rl.tokens < 1 {
		return false
	}

	rl.tokens--
	return true
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if config.Auth.TokenTTL == "" {
		config.Auth.TokenTTL = "1h"
	}
	if config.Seal.SecretShares == 0 {
		config.Seal.SecretShares = 5
	}
	if config.Seal.SecretThreshold == 0 {
		config.Seal.SecretThreshold = 3
	}

	return &config, nil
}

// NewServer creates a new Vaultrix server
func NewServer(config *Config) (*Server, error) {
	// Initialize seal manager
	sealMgr := seal.NewManager(config.Storage.Path)
	if err := sealMgr.LoadState(); err != nil {
		return nil, fmt.Errorf("failed to load seal state: %w", err)
	}

	// Create encryption key provider that gets key from seal manager
	keyProvider := func() ([]byte, error) {
		return sealMgr.GetEncryptionKey()
	}

	// Initialize storage backend
	var storageBackend storage.Backend
	var err error

	switch config.Storage.Type {
	case "file":
		if err := os.MkdirAll(config.Storage.Path, 0700); err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %w", err)
		}
		storageBackend, err = storage.NewFileBackend(config.Storage.Path, keyProvider)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.Storage.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage backend: %w", err)
	}

	// Initialize policy manager
	policyManager, err := policy.NewManager(filepath.Join(config.Storage.Path, "policies"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy manager: %w", err)
	}

	// Initialize audit logger
	var auditLog audit.Logger
	if config.Audit.Enabled {
		auditPath := config.Audit.Path
		if auditPath == "" {
			auditPath = filepath.Join(config.Storage.Path, "audit", "audit.log")
		}
		if err := os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create audit directory: %w", err)
		}
		auditLog, err = audit.NewFileLogger(auditPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
		}
	} else {
		auditLog = &audit.NopLogger{}
	}

	// Initialize rate limiter
	var limiter *RateLimiter
	if config.RateLimit.Enabled {
		rate := config.RateLimit.RequestsPerSec
		if rate <= 0 {
			rate = 100
		}
		burst := config.RateLimit.Burst
		if burst <= 0 {
			burst = 200
		}
		limiter = NewRateLimiter(rate, burst)
	}

	server := &Server{
		config:           config,
		storage:          storageBackend,
		policies:         policyManager,
		sealManager:      sealMgr,
		auditLogger:      auditLog,
		tokens:           make(map[string]TokenInfo),
		replicationLog:   make([]ReplicationEntry, 0),
		replicationReady: make(chan struct{}),
		rateLimiter:      limiter,
		tokenStorePath:   filepath.Join(config.Storage.Path, "tokens.enc"),
	}

	// Set up HTTP server
	mux := http.NewServeMux()
	server.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port),
		Handler:      server.middleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Register API endpoints
	mux.HandleFunc("GET /v1/health", server.healthCheckHandler)

	// System endpoints (available even when sealed)
	mux.HandleFunc("GET /v1/sys/seal-status", server.sealStatusHandler)
	mux.HandleFunc("POST /v1/sys/init", server.initHandler)
	mux.HandleFunc("POST /v1/sys/unseal", server.unsealHandler)
	mux.HandleFunc("POST /v1/sys/seal", server.sealHandler)
	mux.HandleFunc("GET /v1/sys/status", server.systemStatusHandler)
	mux.HandleFunc("GET /v1/sys/replication/status", server.replicationStatusHandler)

	// Secret endpoints
	mux.HandleFunc("POST /v1/secret/{path...}", server.writeSecretHandler)
	mux.HandleFunc("GET /v1/secret/metadata/{path...}", server.getSecretMetadataHandler)
	mux.HandleFunc("GET /v1/secret/versions/{version}/{path...}", server.getSecretVersionHandler)
	mux.HandleFunc("GET /v1/secret/list/{path...}", server.listSecretsHandler)
	mux.HandleFunc("GET /v1/secret/{path...}", server.readSecretHandler)
	mux.HandleFunc("DELETE /v1/secret/{path...}", server.deleteSecretHandler)

	// Policy endpoints
	mux.HandleFunc("POST /v1/policies", server.createPolicyHandler)
	mux.HandleFunc("GET /v1/policies/{name}", server.getPolicyHandler)
	mux.HandleFunc("PUT /v1/policies/{name}", server.updatePolicyHandler)
	mux.HandleFunc("DELETE /v1/policies/{name}", server.deletePolicyHandler)
	mux.HandleFunc("GET /v1/policies", server.listPoliciesHandler)

	// Token endpoints
	mux.HandleFunc("POST /v1/auth/token/create", server.createTokenHandler)
	mux.HandleFunc("GET /v1/auth/token/lookup-self", server.lookupTokenHandler)
	mux.HandleFunc("POST /v1/auth/token/renew-self", server.renewTokenHandler)
	mux.HandleFunc("POST /v1/auth/token/revoke-self", server.revokeTokenHandler)

	// Audit endpoint
	mux.HandleFunc("GET /v1/audit/events", server.auditEventsHandler)

	// Replication endpoint
	mux.HandleFunc("POST /v1/replication/data", server.handleReplicationData)

	// Web UI - serve at /ui/ with SPA routing
	mux.Handle("/ui/", http.StripPrefix("/ui", ui.Handler()))

	// Create root policy
	rootPolicy := &policy.Policy{
		Name:        "root",
		Description: "Root policy with full access",
		Rules: []policy.PathRule{
			{
				Path: "*",
				Capabilities: []policy.Capability{
					policy.CreateCapability,
					policy.ReadCapability,
					policy.UpdateCapability,
					policy.DeleteCapability,
					policy.ListCapability,
				},
			},
		},
	}

	if err := server.policies.CreatePolicy(rootPolicy); err != nil {
		if !vaulterrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("failed to create root policy: %w", err)
		}
	}

	// Initialize cluster role
	switch config.Replication.Mode {
	case "leader":
		server.activeRole = "leader"
		if config.Replication.LeaderAPIAddr == "" {
			server.leaderAddr = fmt.Sprintf("http://%s:%d", config.Server.Address, config.Server.Port)
		} else {
			server.leaderAddr = config.Replication.LeaderAPIAddr
		}
		server.leaderAlive = true
	case "follower":
		server.activeRole = "follower"
		// Derive leader API address from first peer's cluster addr
		if config.Replication.LeaderAPIAddr != "" {
			server.leaderAddr = config.Replication.LeaderAPIAddr
		} else if len(config.Replication.Peers) > 0 {
			// Best-effort: assume leader API is on port 8200 at the same host
			parts := strings.Split(config.Replication.Peers[0], ":")
			if len(parts) >= 1 {
				server.leaderAddr = fmt.Sprintf("http://%s:8200", parts[0])
			}
		}
		server.leaderAlive = true
	default:
		server.activeRole = "standalone"
		server.leaderAlive = true
	}

	// Load persisted tokens if vault is unsealed
	if !sealMgr.IsSealed() {
		server.loadTokens()
	}

	return server, nil
}

// middleware wraps handlers with rate limiting and request size limits
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if s.rateLimiter != nil && !s.rateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Request body size limit
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)
		}

		next.ServeHTTP(w, r)
	})
}

// requireUnseal is a helper that checks if the vault is unsealed
func (s *Server) requireUnseal(w http.ResponseWriter) bool {
	if s.sealManager.IsSealed() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "vault is sealed",
			"sealed": true,
		})
		return false
	}
	return true
}

// Start starts the server
func (s *Server) Start() error {
	// Initialize replication
	if s.config.Replication.Mode == "leader" || s.config.Replication.Mode == "follower" {
		replicationMux := http.NewServeMux()
		replicationMux.HandleFunc("/v1/replication/status", s.replicationClusterStatusHandler)
		replicationMux.HandleFunc("/v1/replication/data", s.replicationDataHandler)

		s.replicationServer = &http.Server{
			Addr:    s.config.Replication.ClusterAddr,
			Handler: s.replicationAuthMiddleware(replicationMux),
		}

		go func() {
			log.Printf("Starting replication server on %s", s.config.Replication.ClusterAddr)
			s.replicationStarted = true

			// Use TLS for replication if TLS is enabled
			if s.config.Server.TLS.Enabled {
				cert, err := tls.LoadX509KeyPair(s.config.Server.TLS.CertFile, s.config.Server.TLS.KeyFile)
				if err != nil {
					log.Printf("Replication TLS error: %v, falling back to plaintext", err)
					if err := s.replicationServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						log.Printf("Replication server error: %v", err)
					}
					return
				}
				s.replicationServer.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				}
				if err := s.replicationServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					log.Printf("Replication server error: %v", err)
				}
			} else {
				if err := s.replicationServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("Replication server error: %v", err)
				}
			}
		}()

		time.Sleep(500 * time.Millisecond)
		close(s.replicationReady)

		if s.config.Replication.Mode == "leader" && len(s.config.Replication.Peers) > 0 {
			go s.startReplicationSync()
		}

		// Start leader health monitor on followers for failover
		if s.config.Replication.Mode == "follower" {
			ctx, cancel := context.WithCancel(context.Background())
			s.failoverCancel = cancel
			go s.startLeaderHealthMonitor(ctx)
		}
	}

	// Start main HTTP server
	if s.config.Server.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(s.config.Server.TLS.CertFile, s.config.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificates: %w", err)
		}

		s.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		return s.httpServer.ListenAndServeTLS("", "")
	}

	log.Println("WARNING: TLS is disabled. This is not recommended for production use.")
	return s.httpServer.ListenAndServe()
}

// SealManager returns the seal manager
func (s *Server) SealManager() *seal.Manager {
	return s.sealManager
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error

	// Stop failover monitor
	if s.failoverCancel != nil {
		s.failoverCancel()
	}

	// Persist tokens before shutdown
	s.persistTokens()

	// Close audit logger
	if s.auditLogger != nil {
		if err := s.auditLogger.Close(); err != nil {
			errs = append(errs, fmt.Errorf("error closing audit logger: %w", err))
		}
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down HTTP server: %w", err))
	}

	if s.replicationServer != nil && s.replicationStarted {
		if err := s.replicationServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("error shutting down replication server: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// --- Token persistence ---

func (s *Server) persistTokens() {
	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()

	if s.sealManager.IsSealed() {
		return
	}

	data, err := json.Marshal(s.tokens)
	if err != nil {
		log.Printf("Failed to marshal tokens: %v", err)
		return
	}

	key, err := s.sealManager.GetEncryptionKey()
	if err != nil {
		log.Printf("Failed to get encryption key for token persistence: %v", err)
		return
	}

	encrypted, err := encryptData(key, data)
	if err != nil {
		log.Printf("Failed to encrypt tokens: %v", err)
		return
	}

	if err := os.WriteFile(s.tokenStorePath, encrypted, 0600); err != nil {
		log.Printf("Failed to persist tokens: %v", err)
	}
}

func (s *Server) loadTokens() {
	data, err := os.ReadFile(s.tokenStorePath)
	if err != nil {
		return // No persisted tokens
	}

	key, err := s.sealManager.GetEncryptionKey()
	if err != nil {
		log.Printf("Failed to get encryption key for token loading: %v", err)
		return
	}

	decrypted, err := decryptData(key, data)
	if err != nil {
		log.Printf("Failed to decrypt tokens: %v", err)
		return
	}

	var tokens map[string]TokenInfo
	if err := json.Unmarshal(decrypted, &tokens); err != nil {
		log.Printf("Failed to unmarshal tokens: %v", err)
		return
	}

	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()

	// Only load non-expired tokens
	now := time.Now()
	for id, info := range tokens {
		if now.Before(info.ExpiresAt) {
			s.tokens[id] = info
		}
	}

	log.Printf("Loaded %d persisted tokens", len(s.tokens))
}

// --- System handlers ---

func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	httpStatus := http.StatusOK
	if s.sealManager.IsSealed() {
		status = "sealed"
		httpStatus = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      status,
		"initialized": s.sealManager.IsInitialized(),
		"sealed":      s.sealManager.IsSealed(),
		"role":        s.getRole(),
		"leader_addr": s.getLeaderAddr(),
	})
}

func (s *Server) sealStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.sealManager.GetStatus())
}

func (s *Server) initHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecretShares    int `json:"secret_shares"`
		SecretThreshold int `json:"secret_threshold"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SecretShares == 0 {
		req.SecretShares = s.config.Seal.SecretShares
	}
	if req.SecretThreshold == 0 {
		req.SecretThreshold = s.config.Seal.SecretThreshold
	}

	resp, err := s.sealManager.Initialize(req.SecretShares, req.SecretThreshold)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to initialize: %v", err), http.StatusBadRequest)
		return
	}

	// Store the root token
	s.tokenMutex.Lock()
	s.tokens[resp.RootToken] = TokenInfo{
		ID:        resp.RootToken,
		PolicyIDs: []string{"root"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	s.tokenMutex.Unlock()

	s.persistTokens()

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventInit,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) unsealHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	unsealed, err := s.sealManager.SubmitUnsealKey(req.Key)
	if err != nil {
		s.auditLogger.Log(audit.Event{
			Timestamp:  time.Now(),
			Type:       audit.EventUnseal,
			RemoteAddr: r.RemoteAddr,
			Success:    false,
			Error:      err.Error(),
		})
		http.Error(w, fmt.Sprintf("Unseal failed: %v", err), http.StatusBadRequest)
		return
	}

	if unsealed {
		// Load persisted tokens now that we're unsealed
		s.loadTokens()

		s.auditLogger.Log(audit.Event{
			Timestamp:  time.Now(),
			Type:       audit.EventUnseal,
			RemoteAddr: r.RemoteAddr,
			Success:    true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.sealManager.GetStatus())
}

func (s *Server) sealHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	// Require authentication to seal
	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Only root policy can seal
	if !s.checkPermission(tokenInfo, "sys/seal", policy.UpdateCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	// Persist tokens before sealing
	s.persistTokens()

	if err := s.sealManager.Seal(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to seal: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSeal,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.sealManager.GetStatus())
}

func (s *Server) systemStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sealed":      s.sealManager.IsSealed(),
		"initialized": s.sealManager.IsInitialized(),
		"replication": s.config.Replication.Mode,
		"server_addr": fmt.Sprintf("%s:%d", s.config.Server.Address, s.config.Server.Port),
	})
}

// --- Token handlers ---

func (s *Server) createTokenHandler(w http.ResponseWriter, r *http.Request) {
	if s.forwardToLeader(w, r) {
		return
	}
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		s.auditLogger.Log(audit.Event{
			Timestamp:  time.Now(),
			Type:       audit.EventAuthFailed,
			RemoteAddr: r.RemoteAddr,
			Success:    false,
			Error:      err.Error(),
		})
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(tokenInfo, "auth/token/create", policy.CreateCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	var req struct {
		PolicyIDs []string `json:"policy_ids"`
		TTL       string   `json:"ttl,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate cryptographically secure token
	newToken, err := seal.GenerateToken()
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	ttl := s.config.Auth.TokenTTL
	if req.TTL != "" {
		ttl = req.TTL
	}

	duration, err := time.ParseDuration(ttl)
	if err != nil {
		http.Error(w, "Invalid TTL format", http.StatusBadRequest)
		return
	}

	now := time.Now()
	s.tokenMutex.Lock()
	s.tokens[newToken] = TokenInfo{
		ID:        newToken,
		PolicyIDs: req.PolicyIDs,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
	}
	s.tokenMutex.Unlock()

	s.persistTokens()

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventTokenCreate,
		TokenID:    tokenID,
		PolicyIDs:  req.PolicyIDs,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token": newToken,
			"policies":     req.PolicyIDs,
			"ttl":          ttl,
		},
	})
}

func (s *Server) lookupTokenHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventTokenLookup,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"id":          tokenInfo.ID,
			"policies":    tokenInfo.PolicyIDs,
			"expire_time": tokenInfo.ExpiresAt.Format(time.RFC3339),
			"created_at":  tokenInfo.CreatedAt.Format(time.RFC3339),
			"ttl":         int(time.Until(tokenInfo.ExpiresAt).Seconds()),
		},
	})
}

func (s *Server) renewTokenHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	_, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	var req struct {
		TTL string `json:"ttl,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	ttl := s.config.Auth.TokenTTL
	if req.TTL != "" {
		ttl = req.TTL
	}

	duration, err := time.ParseDuration(ttl)
	if err != nil {
		http.Error(w, "Invalid TTL format", http.StatusBadRequest)
		return
	}

	s.tokenMutex.Lock()
	if info, exists := s.tokens[tokenID]; exists {
		info.ExpiresAt = time.Now().Add(duration)
		s.tokens[tokenID] = info
	}
	s.tokenMutex.Unlock()

	s.persistTokens()

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventTokenRenew,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	_, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	s.tokenMutex.Lock()
	delete(s.tokens, tokenID)
	s.tokenMutex.Unlock()

	s.persistTokens()

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventTokenRevoke,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

// --- Secret handlers ---

func (s *Server) writeSecretHandler(w http.ResponseWriter, r *http.Request) {
	// Forward writes to leader BEFORE auth check — leader has the tokens
	if s.forwardToLeader(w, r) {
		return
	}

	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		s.auditLogger.Log(audit.Event{
			Timestamp:  time.Now(),
			Type:       audit.EventAuthFailed,
			RemoteAddr: r.RemoteAddr,
			Success:    false,
			Error:      err.Error(),
		})
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")

	// Check if secret exists to determine create vs update capability
	_, metaErr := s.storage.GetSecretMetadata(path)
	isNew := vaulterrors.IsNotFound(metaErr)

	requiredCap := policy.UpdateCapability
	if isNew {
		requiredCap = policy.CreateCapability
	}

	if !s.checkPermission(tokenInfo, path, requiredCap) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	secretData, ok := reqBody["data"].(map[string]interface{})
	if !ok {
		secretData = reqBody
	}

	var metadata map[string]interface{}
	if metaRaw, hasMetadata := reqBody["metadata"].(map[string]interface{}); hasMetadata {
		metadata = metaRaw
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	err = s.storage.WriteSecret(path, secretData, storage.WriteOptions{
		UserID:   tokenID,
		Metadata: metadata,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to store secret: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSecretWrite,
		Path:       path,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	// Replicate
	if s.config.Replication.Mode == "leader" {
		s.addReplicationEntry("write", path, secretData, metadata)
		s.replicateToFollowers(path, secretData, metadata)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) readSecretHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")

	if !s.checkPermission(tokenInfo, path, policy.ReadCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	secret, err := s.storage.ReadSecret(path, storage.ReadOptions{Version: 0})
	if err != nil {
		statusCode := http.StatusInternalServerError
		if vaulterrors.IsNotFound(err) {
			statusCode = http.StatusNotFound
		} else if vaulterrors.IsVersionDestroyed(err) {
			statusCode = http.StatusGone
		}

		s.auditLogger.Log(audit.Event{
			Timestamp:  time.Now(),
			Type:       audit.EventSecretRead,
			Path:       path,
			TokenID:    tokenID,
			RemoteAddr: r.RemoteAddr,
			Success:    false,
			Error:      err.Error(),
		})
		http.Error(w, fmt.Sprintf("Failed to read secret: %v", err), statusCode)
		return
	}

	metadata, _ := s.storage.GetSecretMetadata(path)

	response := map[string]interface{}{
		"data": secret.Data,
		"metadata": map[string]interface{}{
			"created_time": secret.CreatedTime.Format(time.RFC3339),
			"created_by":   secret.CreatedBy,
			"version":      secret.Version,
		},
	}

	if metadata != nil {
		metaMap := response["metadata"].(map[string]interface{})
		metaMap["current_version"] = metadata.CurrentVersion
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSecretRead,
		Path:       path,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	if s.forwardToLeader(w, r) {
		return
	}
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")

	if !s.checkPermission(tokenInfo, path, policy.DeleteCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	query := r.URL.Query()
	versionsParam := query.Get("versions")
	destroyParam := query.Get("destroy")

	options := storage.DeleteOptions{
		UserID:  tokenID,
		Destroy: destroyParam == "true",
	}

	if versionsParam != "" {
		versionStrs := strings.Split(versionsParam, ",")
		versions := make([]int, 0, len(versionStrs))
		for _, vStr := range versionStrs {
			v, err := strconv.Atoi(vStr)
			if err == nil && v > 0 {
				versions = append(versions, v)
			}
		}
		options.Versions = versions
	}

	err = s.storage.DeleteSecret(path, options)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if vaulterrors.IsNotFound(err) {
			statusCode = http.StatusNotFound
		}
		http.Error(w, fmt.Sprintf("Failed to delete secret: %v", err), statusCode)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSecretDelete,
		Path:       path,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSecretMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")

	if !s.checkPermission(tokenInfo, path, policy.ReadCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	metadata, err := s.storage.GetSecretMetadata(path)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if vaulterrors.IsNotFound(err) {
			statusCode = http.StatusNotFound
		}
		http.Error(w, fmt.Sprintf("Failed to get metadata: %v", err), statusCode)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSecretMetadata,
		Path:       path,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	response := map[string]interface{}{
		"versions":        metadata.Versions,
		"current_version": metadata.CurrentVersion,
		"created_time":    metadata.CreatedTime.Format(time.RFC3339),
		"last_modified":   metadata.LastModified.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) listSecretsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")

	if !s.checkPermission(tokenInfo, path, policy.ListCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	secrets, err := s.storage.ListSecrets(path)
	if err != nil {
		if !vaulterrors.IsNotFound(err) {
			http.Error(w, fmt.Sprintf("Failed to list secrets: %v", err), http.StatusInternalServerError)
			return
		}
		secrets = []string{}
	}

	// Strip the prefix so results are relative to the listed path
	prefix := path
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	relative := make([]string, 0, len(secrets))
	for _, s := range secrets {
		rel := strings.TrimPrefix(s, prefix)
		if rel != "" {
			// Only keep the first path segment (immediate children)
			if idx := strings.Index(rel, "/"); idx >= 0 {
				rel = rel[:idx+1] // keep trailing slash for directories
			}
			// Deduplicate
			found := false
			for _, existing := range relative {
				if existing == rel {
					found = true
					break
				}
			}
			if !found {
				relative = append(relative, rel)
			}
		}
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventSecretList,
		Path:       path,
		TokenID:    tokenID,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	response := map[string]interface{}{
		"keys": relative,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) getSecretVersionHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	tokenID := r.Header.Get("X-Vault-Token")
	tokenInfo, err := s.validateToken(tokenID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	path := r.PathValue("path")
	versionStr := r.PathValue("version")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		http.Error(w, "Invalid version number", http.StatusBadRequest)
		return
	}

	if !s.checkPermission(tokenInfo, path, policy.ReadCapability) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	secret, err := s.storage.ReadSecret(path, storage.ReadOptions{Version: version})
	if err != nil {
		statusCode := http.StatusInternalServerError
		if vaulterrors.IsNotFound(err) || vaulterrors.IsVersionNotFound(err) {
			statusCode = http.StatusNotFound
		} else if vaulterrors.IsVersionDestroyed(err) {
			statusCode = http.StatusGone
		}
		http.Error(w, fmt.Sprintf("Version error: %v", err), statusCode)
		return
	}

	response := map[string]interface{}{
		"data": secret.Data,
		"metadata": map[string]interface{}{
			"created_time": secret.CreatedTime.Format(time.RFC3339),
			"created_by":   secret.CreatedBy,
			"version":      secret.Version,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- Policy handlers ---

func (s *Server) createPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if s.forwardToLeader(w, r) {
		return
	}
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(token, "policies", policy.CreateCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	var policyRequest struct {
		Policy policy.Policy `json:"policy"`
	}

	if err := json.NewDecoder(r.Body).Decode(&policyRequest); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.policies.CreatePolicy(&policyRequest.Policy); err != nil {
		if vaulterrors.IsAlreadyExists(err) {
			http.Error(w, "policy already exists", http.StatusConflict)
			return
		}
		http.Error(w, fmt.Sprintf("failed to create policy: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventPolicyCreate,
		Path:       policyRequest.Policy.Name,
		TokenID:    r.Header.Get("X-Vault-Token"),
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(token, "policies", policy.ReadCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	policyName := r.PathValue("name")
	if policyName == "" {
		http.Error(w, "policy name is required", http.StatusBadRequest)
		return
	}

	p, err := s.policies.GetPolicy(policyName)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if vaulterrors.IsNotFound(err) {
			statusCode = http.StatusNotFound
		}
		http.Error(w, fmt.Sprintf("failed to get policy: %v", err), statusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policy": p,
	})
}

func (s *Server) updatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	if s.forwardToLeader(w, r) {
		return
	}
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(token, "policies", policy.UpdateCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	policyName := r.PathValue("name")
	if policyName == "" {
		http.Error(w, "policy name is required", http.StatusBadRequest)
		return
	}

	var policyRequest struct {
		Policy policy.Policy `json:"policy"`
	}

	if err := json.NewDecoder(r.Body).Decode(&policyRequest); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	if policyName != policyRequest.Policy.Name {
		http.Error(w, "policy name in URL does not match request body", http.StatusBadRequest)
		return
	}

	if err := s.policies.UpdatePolicy(&policyRequest.Policy); err != nil {
		http.Error(w, fmt.Sprintf("failed to update policy: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventPolicyUpdate,
		Path:       policyName,
		TokenID:    r.Header.Get("X-Vault-Token"),
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	if s.forwardToLeader(w, r) {
		return
	}
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(token, "policies", policy.DeleteCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	policyName := r.PathValue("name")
	if policyName == "" {
		http.Error(w, "policy name is required", http.StatusBadRequest)
		return
	}

	if err := s.policies.DeletePolicy(policyName); err != nil {
		http.Error(w, fmt.Sprintf("failed to delete policy: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventPolicyDelete,
		Path:       policyName,
		TokenID:    r.Header.Get("X-Vault-Token"),
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.checkPermission(token, "policies", policy.ListCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	policies := s.policies.ListPolicies()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
	})
}

// --- Audit handler ---

func (s *Server) auditEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnseal(w) {
		return
	}

	token, err := s.validateToken(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Only root policy can view audit logs
	if !s.checkPermission(token, "sys/audit", policy.ReadCapability) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	filter := audit.QueryFilter{}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}
	if eventType := r.URL.Query().Get("type"); eventType != "" {
		filter.Type = audit.EventType(eventType)
	}
	if path := r.URL.Query().Get("path"); path != "" {
		filter.Path = path
	}

	events, err := s.auditLogger.Query(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query audit events: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
	})
}

// --- Authentication ---

func (s *Server) validateToken(tokenID string) (*TokenInfo, error) {
	if tokenID == "" {
		return nil, vaulterrors.ErrInvalidToken
	}

	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()

	tokenInfo, exists := s.tokens[tokenID]
	if !exists {
		return nil, vaulterrors.ErrInvalidToken
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, vaulterrors.ErrTokenExpired
	}

	return &tokenInfo, nil
}

func (s *Server) checkPermission(token *TokenInfo, path string, capability policy.Capability) bool {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	// Check for root policy
	for _, policyID := range token.PolicyIDs {
		if policyID == "root" {
			return true
		}
	}

	return s.policies.CheckPermission(token.PolicyIDs, path, capability)
}

// --- Write Forwarding & Failover ---

// isLeader returns true if this node is the active leader
func (s *Server) isLeader() bool {
	s.clusterMu.RLock()
	defer s.clusterMu.RUnlock()
	return s.activeRole == "leader" || s.activeRole == "standalone"
}

// getLeaderAddr returns the current leader's API address
func (s *Server) getLeaderAddr() string {
	s.clusterMu.RLock()
	defer s.clusterMu.RUnlock()
	return s.leaderAddr
}

// getRole returns the current role
func (s *Server) getRole() string {
	s.clusterMu.RLock()
	defer s.clusterMu.RUnlock()
	return s.activeRole
}

// forwardToLeader forwards a write request to the leader node.
// Returns true if the request was forwarded (caller should not process it).
// Returns false if this node IS the leader (caller should process normally).
func (s *Server) forwardToLeader(w http.ResponseWriter, r *http.Request) bool {
	if s.isLeader() {
		return false // we are the leader, handle locally
	}

	leaderAddr := s.getLeaderAddr()
	if leaderAddr == "" {
		http.Error(w, "No leader available — cluster may be in failover", http.StatusServiceUnavailable)
		return true
	}

	// Build the forwarded URL
	targetURL := leaderAddr + r.URL.RequestURI()

	// Read the original body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return true
	}

	// Create forwarded request
	fwdReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "Failed to create forwarded request", http.StatusInternalServerError)
		return true
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			fwdReq.Header.Add(key, v)
		}
	}
	fwdReq.Header.Set("X-Forwarded-By", s.config.Replication.ClusterAddr)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(fwdReq)
	if err != nil {
		log.Printf("Failed to forward write to leader %s: %v", leaderAddr, err)
		http.Error(w, "Leader unavailable — write could not be forwarded", http.StatusBadGateway)
		return true
	}
	defer resp.Body.Close()

	// Copy the leader's response back to the client
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Vault-Forward", "true")
	w.Header().Set("X-Vault-Leader", leaderAddr)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return true
}

// startLeaderHealthMonitor runs on followers, periodically checking if the leader is alive.
// If the leader is down for longer than FailoverTimeoutSec, the first follower promotes itself.
func (s *Server) startLeaderHealthMonitor(ctx context.Context) {
	if s.activeRole != "follower" {
		return
	}

	checkInterval := time.Duration(s.config.Replication.HealthCheckSec) * time.Second
	if checkInterval <= 0 {
		checkInterval = 5 * time.Second
	}
	failoverTimeout := time.Duration(s.config.Replication.FailoverTimeoutSec) * time.Second
	if failoverTimeout <= 0 {
		failoverTimeout = 30 * time.Second
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	var downSince time.Time
	client := &http.Client{Timeout: 3 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			leaderAddr := s.getLeaderAddr()
			if leaderAddr == "" {
				continue
			}

			healthURL := leaderAddr + "/v1/health"
			resp, err := client.Get(healthURL)
			if err != nil || resp.StatusCode == 0 {
				// Leader is unreachable
				if downSince.IsZero() {
					downSince = time.Now()
					log.Printf("Leader %s is unreachable, starting failover timer (%v)", leaderAddr, failoverTimeout)
				}

				if time.Since(downSince) >= failoverTimeout {
					log.Printf("Leader %s has been down for %v — promoting to leader", leaderAddr, time.Since(downSince))
					s.promoteToLeader()
					return // stop monitoring, we are now the leader
				}
			} else {
				resp.Body.Close()
				if !downSince.IsZero() {
					log.Printf("Leader %s is back online, cancelling failover", leaderAddr)
					downSince = time.Time{} // reset
				}
				s.clusterMu.Lock()
				s.leaderAlive = true
				s.clusterMu.Unlock()
			}
		}
	}
}

// promoteToLeader promotes this follower to leader
func (s *Server) promoteToLeader() {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()

	s.activeRole = "leader"
	s.leaderAddr = fmt.Sprintf("http://%s:%d", s.config.Server.Address, s.config.Server.Port)
	s.leaderAlive = true

	log.Printf("*** This node has been PROMOTED to leader (addr: %s) ***", s.leaderAddr)

	s.auditLogger.Log(audit.Event{
		Timestamp: time.Now(),
		Type:      audit.EventType("sys.failover"),
		Success:   true,
		Metadata: map[string]interface{}{
			"new_role":    "leader",
			"new_address": s.leaderAddr,
		},
	})

	// Start replicating to remaining peers
	if len(s.config.Replication.Peers) > 0 {
		go s.startReplicationSync()
	}
}

// --- Replication ---

func (s *Server) replicationAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.Replication.SharedSecret != "" {
			authHeader := r.Header.Get("X-Replication-Token")
			if authHeader != s.config.Replication.SharedSecret {
				http.Error(w, "Unauthorized replication request", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) addReplicationEntry(op, path string, data, metadata map[string]interface{}) {
	s.repLogMutex.Lock()
	defer s.repLogMutex.Unlock()

	s.repLogNextID++
	s.replicationLog = append(s.replicationLog, ReplicationEntry{
		ID:        s.repLogNextID,
		Operation: op,
		Path:      path,
		Data:      data,
		Metadata:  metadata,
		Timestamp: time.Now().Unix(),
	})

	// Bound the replication log to 10000 entries
	const maxLogSize = 10000
	if len(s.replicationLog) > maxLogSize {
		s.replicationLog = s.replicationLog[len(s.replicationLog)-maxLogSize:]
	}
}

func (s *Server) replicateToFollowers(path string, data, metadata map[string]interface{}) {
	if len(s.config.Replication.Peers) == 0 {
		return
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(s.config.Replication.Peers))

	for _, peer := range s.config.Replication.Peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			if err := s.syncToFollower(peer, path, data, metadata); err != nil {
				errs <- fmt.Errorf("failed to replicate to %s: %v", peer, err)
			}
		}(peer)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		log.Printf("Replication error: %v", err)
	}
}

func (s *Server) handleReplicationData(w http.ResponseWriter, r *http.Request) {
	if s.config.Replication.Mode != "follower" {
		http.Error(w, "Not a follower node", http.StatusBadRequest)
		return
	}

	// Verify replication auth
	if s.config.Replication.SharedSecret != "" {
		if r.Header.Get("X-Replication-Token") != s.config.Replication.SharedSecret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var replicationData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&replicationData); err != nil {
		http.Error(w, fmt.Sprintf("Invalid replication data: %v", err), http.StatusBadRequest)
		return
	}

	pathRaw, ok := replicationData["path"]
	if !ok {
		http.Error(w, "Missing path", http.StatusBadRequest)
		return
	}
	path, ok := pathRaw.(string)
	if !ok {
		http.Error(w, "Path must be a string", http.StatusBadRequest)
		return
	}

	dataRaw, ok := replicationData["data"]
	if !ok {
		http.Error(w, "Missing data", http.StatusBadRequest)
		return
	}
	data, ok := dataRaw.(map[string]interface{})
	if !ok {
		http.Error(w, "Data must be an object", http.StatusBadRequest)
		return
	}

	metadataRaw, _ := replicationData["metadata"]
	metadata, _ := metadataRaw.(map[string]interface{})

	err := s.storage.WriteSecret(path, data, storage.WriteOptions{
		UserID:        "replication",
		Metadata:      metadata,
		IsReplication: true,
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to store replicated data: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.Log(audit.Event{
		Timestamp:  time.Now(),
		Type:       audit.EventReplicationSync,
		Path:       path,
		RemoteAddr: r.RemoteAddr,
		Success:    true,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *Server) replicationStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"mode":         s.config.Replication.Mode,
		"server_id":    fmt.Sprintf("%s:%d", s.config.Server.Address, s.config.Server.Port),
		"cluster_addr": s.config.Replication.ClusterAddr,
		"peers":        s.config.Replication.Peers,
		"timestamp":    time.Now().Unix(),
	}

	if s.config.Replication.Mode == "leader" {
		s.repLogMutex.RLock()
		status["log_size"] = len(s.replicationLog)
		s.repLogMutex.RUnlock()
	}

	json.NewEncoder(w).Encode(status)
}

func (s *Server) replicationClusterStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.replicationStatusHandler(w, r)
}

func (s *Server) replicationDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.config.Replication.Mode != "follower" {
		http.Error(w, "Server is not in follower mode", http.StatusForbidden)
		return
	}

	// Verify replication auth
	if s.config.Replication.SharedSecret != "" {
		if r.Header.Get("X-Replication-Token") != s.config.Replication.SharedSecret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var replicationData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&replicationData); err != nil {
		http.Error(w, "Invalid replication data format", http.StatusBadRequest)
		return
	}

	if path, ok := replicationData["path"].(string); ok {
		dataRaw, ok := replicationData["data"].(map[string]interface{})
		if !ok {
			http.Error(w, "Invalid data format", http.StatusBadRequest)
			return
		}

		metadataRaw, _ := replicationData["metadata"].(map[string]interface{})

		err := s.storage.WriteSecret(path, dataRaw, storage.WriteOptions{
			UserID:        "replication",
			Metadata:      metadataRaw,
			IsReplication: true,
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to store replicated data: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *Server) startReplicationSync() {
	if s.config.Replication.Mode != "leader" {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastSyncedID int64

	for {
		select {
		case <-ticker.C:
			s.repLogMutex.RLock()
			var entriesToSync []ReplicationEntry
			for _, entry := range s.replicationLog {
				if entry.ID > lastSyncedID {
					entriesToSync = append(entriesToSync, entry)
				}
			}
			s.repLogMutex.RUnlock()

			if len(entriesToSync) == 0 {
				continue
			}

			for _, follower := range s.config.Replication.Peers {
				for _, entry := range entriesToSync {
					if err := s.syncToFollower(follower, entry.Path, entry.Data, entry.Metadata); err != nil {
						log.Printf("Replication error to %s: %v", follower, err)
					}
				}
			}

			if len(entriesToSync) > 0 {
				lastSyncedID = entriesToSync[len(entriesToSync)-1].ID
			}
		}
	}
}

func (s *Server) syncToFollower(peerAddr, path string, data, metadata map[string]interface{}) error {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	replicationData := map[string]interface{}{
		"path":     path,
		"data":     data,
		"metadata": metadata,
	}

	maxRetries := 3
	baseDelay := 100 * time.Millisecond
	for i := 0; i < maxRetries; i++ {
		err := s.sendReplicationData(peerAddr, replicationData)
		if err == nil {
			return nil
		}
		log.Printf("Failed to sync to follower %s (attempt %d/%d): %v", peerAddr, i+1, maxRetries, err)
		delay := baseDelay * time.Duration(1<<uint(i))
		time.Sleep(delay)
	}
	return fmt.Errorf("failed to sync to follower %s after %d attempts", peerAddr, maxRetries)
}

func (s *Server) sendReplicationData(peerAddr string, data map[string]interface{}) error {
	protocol := "http"
	if s.config.Server.TLS.Enabled {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s/v1/replication/data", protocol, peerAddr)

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal replication data: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create replication request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.Replication.SharedSecret != "" {
		req.Header.Set("X-Replication-Token", s.config.Replication.SharedSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send replication data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("replication request failed with status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// --- Encryption helpers ---

func encryptData(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptData(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]
	return aesGCM.Open(nil, nonce, ct, nil)
}

