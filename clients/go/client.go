package securevault

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the SecureVault client that provides methods for interacting with the server
type Client struct {
	config     *Config
	httpClient *http.Client
	token      string
	mu         sync.RWMutex
}

// Config contains the configuration for the SecureVault client
type Config struct {
	// Address is the URL of the SecureVault server
	Address string

	// Token is the authentication token to use
	Token string

	// Timeout for HTTP requests
	Timeout time.Duration

	// MaxRetries is the maximum number of times to retry a request
	MaxRetries int

	// RetryWaitTime is the time to wait between retries
	RetryWaitTime time.Duration

	// InsecureSkipVerify controls whether the client verifies the server's certificate chain
	InsecureSkipVerify bool
}

// Secret represents a secret stored in SecureVault
type Secret struct {
	// Data contains the secret data
	Data map[string]interface{}

	// Metadata contains metadata about the secret
	Metadata struct {
		// CreatedTime is when the secret was created
		CreatedTime time.Time `json:"created_time"`

		// Version is the version of the secret
		Version int `json:"version"`

		// CurrentVersion is the latest version of the secret
		CurrentVersion int `json:"current_version"`
	} `json:"metadata"`
}

// SecretMetadata contains metadata about a secret
type SecretMetadata struct {
	// Versions contains metadata about each version of the secret
	Versions map[string]VersionMetadata `json:"versions"`

	// CurrentVersion is the latest version number
	CurrentVersion int `json:"current_version"`

	// CreatedTime is when the secret was first created
	CreatedTime time.Time `json:"created_time"`

	// LastModified is when the secret was last modified
	LastModified time.Time `json:"last_modified"`
}

// VersionMetadata contains metadata about a specific version of a secret
type VersionMetadata struct {
	// CreatedTime is when this version was created
	CreatedTime time.Time `json:"created_time"`

	// CreatedBy is who created this version
	CreatedBy string `json:"created_by"`

	// DeletedTime is when this version was deleted (if applicable)
	DeletedTime time.Time `json:"deleted_time,omitempty"`

	// DeletedBy is who deleted this version (if applicable)
	DeletedBy string `json:"deleted_by,omitempty"`

	// IsDestroyed indicates if this version has been permanently destroyed
	IsDestroyed bool `json:"is_destroyed"`

	// CustomMetadata contains any custom metadata for this version
	CustomMetadata map[string]interface{} `json:"custom_metadata,omitempty"`
}

// Policy represents an access policy in SecureVault
type Policy struct {
	// Name is the policy's name
	Name string `json:"name"`

	// Description is a human-readable description of the policy
	Description string `json:"description"`

	// Rules defines the access permissions for paths
	Rules []PolicyRule `json:"rules"`
}

// PolicyRule defines access permissions for a path pattern
type PolicyRule struct {
	// Path is the path pattern this rule applies to
	Path string `json:"path"`

	// Capabilities are the operations allowed on this path
	Capabilities []string `json:"capabilities"`
}

// TokenOptions contains options for creating authentication tokens
type TokenOptions struct {
	// PolicyIDs are the policies to associate with the token
	PolicyIDs []string `json:"policy_ids"`

	// TTL is how long the token should be valid for
	TTL string `json:"ttl,omitempty"`
}

// WriteOptions contains options for write operations
type WriteOptions struct {
	// Metadata is custom metadata to associate with the secret
	Metadata map[string]interface{} `json:"-"`
}

// ReadOptions contains options for read operations
type ReadOptions struct {
	// Version is the specific version to read (0 means latest)
	Version int
}

// DeleteOptions contains options for delete operations
type DeleteOptions struct {
	// Versions is a list of versions to delete (empty means all)
	Versions []int

	// Destroy indicates whether to permanently destroy the secret
	Destroy bool
}

// ListOptions contains options for list operations
type ListOptions struct {
	// Recursive indicates whether to list recursively
	Recursive bool
}

// ClientOption is a function that configures a Client
type ClientOption func(*Config)

// WithTimeout sets the timeout for HTTP requests
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Config) {
		c.Timeout = timeout
	}
}

// WithMaxRetries sets the maximum number of times to retry a request
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *Config) {
		c.MaxRetries = maxRetries
	}
}

// WithRetryWaitTime sets the time to wait between retries
func WithRetryWaitTime(waitTime time.Duration) ClientOption {
	return func(c *Config) {
		c.RetryWaitTime = waitTime
	}
}

// WithInsecureSkipVerify controls whether the client verifies the server's certificate
func WithInsecureSkipVerify(skip bool) ClientOption {
	return func(c *Config) {
		c.InsecureSkipVerify = skip
	}
}

// ClientError represents an error from the SecureVault client
type ClientError struct {
	StatusCode int
	Message    string
}

func (e ClientError) Error() string {
	return fmt.Sprintf("SecureVault client error (HTTP %d): %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is due to a resource not being found
func IsNotFound(err error) bool {
	var clientErr ClientError
	return errors.As(err, &clientErr) && clientErr.StatusCode == http.StatusNotFound
}

// IsUnauthorized returns true if the error is due to an authentication failure
func IsUnauthorized(err error) bool {
	var clientErr ClientError
	return errors.As(err, &clientErr) && clientErr.StatusCode == http.StatusUnauthorized
}

// IsForbidden returns true if the error is due to a permission issue
func IsForbidden(err error) bool {
	var clientErr ClientError
	return errors.As(err, &clientErr) && clientErr.StatusCode == http.StatusForbidden
}

// NewClient creates a new SecureVault client with the given configuration
func NewClient(address, token string, options ...ClientOption) (*Client, error) {
	// Validate address
	if address == "" {
		return nil, errors.New("address is required")
	}
	
	// Add protocol if missing
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "https://" + address
	}
	
	// Validate address is a valid URL
	_, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Create default config
	config := &Config{
		Address:       address,
		Token:         token,
		Timeout:       10 * time.Second,
		MaxRetries:    3,
		RetryWaitTime: 1 * time.Second,
	}

	// Apply options
	for _, option := range options {
		option(config)
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.InsecureSkipVerify,
			},
		},
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
		token:      token,
	}, nil
}

// doRequest makes an HTTP request to the SecureVault server with retry logic
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	// Prepare URL
	u, err := url.Parse(c.config.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	u.Path = path
	
	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	c.mu.RLock()
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	c.mu.RUnlock()

	// Execute request with retries
	var resp *http.Response
	var lastErr error
	
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		// Only wait if this is a retry
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.config.RetryWaitTime * time.Duration(attempt)):
				// Continue after wait
			}
		}

		resp, err = c.httpClient.Do(req)
		if err == nil {
			break
		}
		
		lastErr = err
		
		// Don't retry if context cancelled or timeout
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}

	if resp == nil {
		if lastErr != nil {
			return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
		}
		return nil, errors.New("request failed after max retries")
	}
	
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		
		if err := json.Unmarshal(responseBody, &errResp); err == nil && errResp.Error != "" {
			return nil, ClientError{StatusCode: resp.StatusCode, Message: errResp.Error}
		}
		
		// If we can't parse the error, return a generic error
		return nil, ClientError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		}
	}

	return responseBody, nil
}

// WriteSecret writes a secret to the server
func (c *Client) WriteSecret(ctx context.Context, path string, data map[string]interface{}, options ...WriteOptions) error {
	// Process options
	var opts WriteOptions
	if len(options) > 0 {
		opts = options[0]
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"data": data,
	}
	
	if opts.Metadata != nil {
		requestBody["metadata"] = opts.Metadata
	}

	// Make request
	_, err := c.doRequest(ctx, http.MethodPost, "/v1/secret/"+path, requestBody)
	return err
}

// ReadSecret reads a secret from the server
func (c *Client) ReadSecret(ctx context.Context, path string, options ...ReadOptions) (*Secret, error) {
	// Process options
	var opts ReadOptions
	if len(options) > 0 {
		opts = options[0]
	}

	// Build URL
	url := "/v1/secret/" + path
	if opts.Version > 0 {
		url = fmt.Sprintf("/v1/secret/%s/versions/%d", path, opts.Version)
	}

	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Parse response
	var secret Secret
	if err := json.Unmarshal(responseBody, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &secret, nil
}

// DeleteSecret deletes a secret from the server
func (c *Client) DeleteSecret(ctx context.Context, path string, options ...DeleteOptions) error {
	// Process options
	var opts DeleteOptions
	if len(options) > 0 {
		opts = options[0]
	}

	// Build URL
	apiURL := "/v1/secret/" + path
	
	// Add query parameters for options if needed
	if opts.Destroy || len(opts.Versions) > 0 {
		query := url.Values{}
		
		if opts.Destroy {
			query.Set("destroy", "true")
		}
		
		if len(opts.Versions) > 0 {
			versions := make([]string, len(opts.Versions))
			for i, v := range opts.Versions {
				versions[i] = fmt.Sprintf("%d", v)
			}
			query.Set("versions", strings.Join(versions, ","))
		}
		
		apiURL = apiURL + "?" + query.Encode()
	}

	// Make request
	_, err := c.doRequest(ctx, http.MethodDelete, apiURL, nil)
	return err
}

// ListSecrets lists secrets under a path
func (c *Client) ListSecrets(ctx context.Context, path string, options ...ListOptions) ([]string, error) {
	// Process options
	var opts ListOptions
	if len(options) > 0 {
		opts = options[0]
	}

	// Normalize path
	if !strings.HasSuffix(path, "/") && path != "" {
		path += "/"
	}

	// Build URL with query parameters
	url := "/v1/secret/" + path + "?list=true"
	if opts.Recursive {
		url += "&recursive=true"
	}

	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Parse response
	var response struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return response.Keys, nil
}

// GetSecretMetadata gets metadata about a secret
func (c *Client) GetSecretMetadata(ctx context.Context, path string) (*SecretMetadata, error) {
	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodGet, "/v1/secret/"+path+"/metadata", nil)
	if err != nil {
		return nil, err
	}

	// Parse response
	var metadata SecretMetadata
	if err := json.Unmarshal(responseBody, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

// CreatePolicy creates a new policy
func (c *Client) CreatePolicy(ctx context.Context, policy *Policy) error {
	// Make request
	_, err := c.doRequest(ctx, http.MethodPost, "/v1/policies", policy)
	return err
}

// GetPolicy retrieves a policy by name
func (c *Client) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodGet, "/v1/policies/"+name, nil)
	if err != nil {
		return nil, err
	}

	// Parse response
	var policy Policy
	if err := json.Unmarshal(responseBody, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return &policy, nil
}

// UpdatePolicy updates an existing policy
func (c *Client) UpdatePolicy(ctx context.Context, policy *Policy) error {
	// Make request
	_, err := c.doRequest(ctx, http.MethodPut, "/v1/policies/"+policy.Name, policy)
	return err
}

// DeletePolicy deletes a policy
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	// Make request
	_, err := c.doRequest(ctx, http.MethodDelete, "/v1/policies/"+name, nil)
	return err
}

// ListPolicies lists all policies
func (c *Client) ListPolicies(ctx context.Context) ([]string, error) {
	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodGet, "/v1/policies", nil)
	if err != nil {
		return nil, err
	}

	// Parse response
	var response struct {
		Policies []string `json:"policies"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return response.Policies, nil
}

// CreateToken creates a new authentication token
func (c *Client) CreateToken(ctx context.Context, options TokenOptions) (string, error) {
	// Make request
	responseBody, err := c.doRequest(ctx, http.MethodPost, "/v1/auth/token/create", options)
	if err != nil {
		return "", err
	}

	// Parse response
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return response.Token, nil
}

// SetToken updates the token used by the client
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}
