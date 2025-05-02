package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Capability represents an operation that can be performed on a path
type Capability string

const (
	// CreateCapability allows creating new secrets
	CreateCapability Capability = "create"
	// ReadCapability allows reading secrets
	ReadCapability Capability = "read"
	// UpdateCapability allows updating existing secrets
	UpdateCapability Capability = "update"
	// DeleteCapability allows deleting secrets
	DeleteCapability Capability = "delete"
	// ListCapability allows listing secrets in a path
	ListCapability Capability = "list"
)

// IsValid checks if a capability is valid
func (c Capability) IsValid() bool {
	switch c {
	case CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability:
		return true
	default:
		return false
	}
}

// PathRule represents a rule that applies to a specific path or pattern
type PathRule struct {
	Path         string       `json:"path" yaml:"path"`
	Capabilities []Capability `json:"capabilities" yaml:"capabilities"`
	compiledPath *regexp.Regexp
}

// Policy defines a set of permissions
type Policy struct {
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description" yaml:"description"`
	Rules       []PathRule `json:"rules" yaml:"rules"`
}

// Manager manages the policies in the system
type Manager struct {
	policiesDir string
	policies    map[string]*Policy
	mutex       sync.RWMutex
}

// NewManager creates a new policy manager
func NewManager(policiesDir string) (*Manager, error) {
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create policies directory: %w", err)
	}

	manager := &Manager{
		policiesDir: policiesDir,
		policies:    make(map[string]*Policy),
	}

	// Load existing policies
	if err := manager.loadPolicies(); err != nil {
		return nil, err
	}

	return manager, nil
}

// loadPolicies loads all policies from the policies directory
func (m *Manager) loadPolicies() error {
	files, err := os.ReadDir(m.policiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read policies directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || (!strings.HasSuffix(file.Name(), ".yaml") && !strings.HasSuffix(file.Name(), ".yml")) {
			continue
		}

		filePath := filepath.Join(m.policiesDir, file.Name())
		policy, err := m.loadPolicyFromFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to load policy from %s: %w", filePath, err)
		}

		m.policies[policy.Name] = policy
	}

	return nil
}

// loadPolicyFromFile loads a policy from a YAML file
func (m *Manager) loadPolicyFromFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	// Validate and compile path patterns
	if err := m.validateAndCompilePolicy(&policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// validateAndCompilePolicy validates a policy and compiles path patterns
func (m *Manager) validateAndCompilePolicy(policy *Policy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	for i, rule := range policy.Rules {
		if rule.Path == "" {
			return fmt.Errorf("path is required for rule %d", i)
		}

		if len(rule.Capabilities) == 0 {
			return fmt.Errorf("at least one capability is required for path %s", rule.Path)
		}

		for _, cap := range rule.Capabilities {
			if !cap.IsValid() {
				return fmt.Errorf("invalid capability %s for path %s", cap, rule.Path)
			}
		}

		// Convert path pattern to regex
		pattern := pathToRegexPattern(rule.Path)
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid path pattern %s: %w", rule.Path, err)
		}
		policy.Rules[i].compiledPath = regex
	}

	return nil
}

// pathToRegexPattern converts a policy path pattern to a regex pattern
func pathToRegexPattern(path string) string {
	// Special case for global wildcard
	if path == "*" {
		return "^.*$"
	}
	
	// Escape regex special characters except * and /
	pattern := regexp.QuoteMeta(path)
	
	// Replace * with regex pattern for segment match
	pattern = strings.Replace(pattern, "\\*", "[^/]+", -1)
	
	// Add word boundary to ensure exact match
	pattern = "^" + pattern + "$"
	
	return pattern
}

// CreatePolicy creates a new policy
func (m *Manager) CreatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate policy
	if err := m.validateAndCompilePolicy(policy); err != nil {
		return err
	}

	// Check if policy already exists
	if _, exists := m.policies[policy.Name]; exists {
		return fmt.Errorf("policy %s already exists", policy.Name)
	}

	// Save policy to file
	filePath := filepath.Join(m.policiesDir, policy.Name+".yaml")
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	// Add to in-memory cache
	m.policies[policy.Name] = policy

	return nil
}

// GetPolicy retrieves a policy by name
func (m *Manager) GetPolicy(name string) (*Policy, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policy, exists := m.policies[name]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", name)
	}

	return policy, nil
}

// UpdatePolicy updates an existing policy
func (m *Manager) UpdatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate policy
	if err := m.validateAndCompilePolicy(policy); err != nil {
		return err
	}

	// Check if policy exists
	if _, exists := m.policies[policy.Name]; !exists {
		return fmt.Errorf("policy %s not found", policy.Name)
	}

	// Save policy to file
	filePath := filepath.Join(m.policiesDir, policy.Name+".yaml")
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	// Update in-memory cache
	m.policies[policy.Name] = policy

	return nil
}

// DeletePolicy deletes a policy
func (m *Manager) DeletePolicy(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if policy exists
	if _, exists := m.policies[name]; !exists {
		return fmt.Errorf("policy %s not found", name)
	}

	// Delete policy file
	filePath := filepath.Join(m.policiesDir, name+".yaml")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete policy file: %w", err)
	}

	// Remove from in-memory cache
	delete(m.policies, name)

	return nil
}

// ListPolicies returns a list of all policies
func (m *Manager) ListPolicies() []*Policy {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policies := make([]*Policy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}

	return policies
}

// CheckPermission checks if any of the provided policies grant the required capability for the path
func (m *Manager) CheckPermission(policyIDs []string, path string, capability Capability) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Normalize path for consistent matching
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	// First check for root policy with wildcard permissions (optimization)
	for _, policyID := range policyIDs {
		if policyID == "root" {
			rootPolicy, exists := m.policies["root"]
			if exists {
				// Check if root policy grants this capability globally
				for _, rule := range rootPolicy.Rules {
					if rule.Path == "*" {
						for _, cap := range rule.Capabilities {
							if cap == capability {
								return true  // Root policy with wildcard grants this capability
							}
						}
					}
				}
			}
		}
	}

	// Check each policy for permission
	for _, policyID := range policyIDs {
		policy, exists := m.policies[policyID]
		if !exists {
			continue
		}

		if policy.CheckPathPermission(path, capability) {
			return true  // This policy grants the capability
		}
	}

	return false  // No policy grants this capability
}
// CheckPathPermission checks if the policy grants the required capability for the path
func (p *Policy) CheckPathPermission(path string, capability Capability) bool {
	// First check for global wildcard rules (optimization)
	for _, rule := range p.Rules {
		if rule.Path == "*" {
			for _, cap := range rule.Capabilities {
				if cap == capability {
					return true  // Global wildcard matches any path
				}
			}
		}
	}

	// Special case for ListCapability - needs to match parent directories
	if capability == ListCapability {
		// Check if we have list permission on the exact path
		for _, rule := range p.Rules {
			if rule.compiledPath == nil {
				continue
			}

			// Check for exact match first
			if rule.compiledPath.MatchString(path) {
				for _, cap := range rule.Capabilities {
					if cap == ListCapability {
						return true
					}
				}
			}

			// Check for parent path with wildcard
			parentPath := path
			for parentPath != "" {
				if rule.Path == parentPath || rule.Path == parentPath+"/*" {
					for _, cap := range rule.Capabilities {
						if cap == ListCapability {
							return true
						}
					}
				}
				
				// Move up to parent directory
				lastSlash := strings.LastIndex(parentPath, "/")
				if lastSlash == -1 {
					parentPath = ""
				} else {
					parentPath = parentPath[:lastSlash]
				}
			}
		}
	}

	// Check other path-specific rules
	for _, rule := range p.Rules {
		if rule.compiledPath == nil {
			continue  // Skip rules with invalid patterns
		}

		// Check if path matches this rule's pattern
		if rule.compiledPath.MatchString(path) {
			// Check if rule grants the requested capability
			for _, cap := range rule.Capabilities {
				if cap == capability {
					return true
				}
			}
		}
	}

	return false  // No rule grants this capability for this path
}

