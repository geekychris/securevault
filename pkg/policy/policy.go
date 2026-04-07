package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	vaulterrors "securevault/pkg/errors"

	"gopkg.in/yaml.v3"
)

// Capability represents an operation that can be performed on a path
type Capability string

const (
	CreateCapability Capability = "create"
	ReadCapability   Capability = "read"
	UpdateCapability Capability = "update"
	DeleteCapability Capability = "delete"
	ListCapability   Capability = "list"
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
	if err := os.MkdirAll(policiesDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create policies directory: %w", err)
	}

	manager := &Manager{
		policiesDir: policiesDir,
		policies:    make(map[string]*Policy),
	}

	if err := manager.loadPolicies(); err != nil {
		return nil, err
	}

	return manager, nil
}

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

func (m *Manager) loadPolicyFromFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := m.validateAndCompilePolicy(&policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

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

		pattern := pathToRegexPattern(rule.Path)
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid path pattern %s: %w", rule.Path, err)
		}
		policy.Rules[i].compiledPath = regex
	}

	return nil
}

func pathToRegexPattern(path string) string {
	if path == "*" {
		return "^.*$"
	}

	// Handle ** (match any number of path segments) before * (single segment)
	pattern := regexp.QuoteMeta(path)
	// \*\* was escaped from **, replace with match-everything
	pattern = strings.Replace(pattern, "\\*\\*", ".*", -1)
	// \* was escaped from *, replace with single-segment match
	pattern = strings.Replace(pattern, "\\*", "[^/]+", -1)
	pattern = "^" + pattern + "$"

	return pattern
}

// CreatePolicy creates a new policy
func (m *Manager) CreatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.validateAndCompilePolicy(policy); err != nil {
		return err
	}

	if _, exists := m.policies[policy.Name]; exists {
		return &vaulterrors.PolicyExistsError{Name: policy.Name}
	}

	filePath := filepath.Join(m.policiesDir, policy.Name+".yaml")
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	m.policies[policy.Name] = policy
	return nil
}

// GetPolicy retrieves a policy by name
func (m *Manager) GetPolicy(name string) (*Policy, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policy, exists := m.policies[name]
	if !exists {
		return nil, &vaulterrors.PolicyNotFoundError{Name: name}
	}

	return policy, nil
}

// UpdatePolicy updates an existing policy
func (m *Manager) UpdatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.validateAndCompilePolicy(policy); err != nil {
		return err
	}

	if _, exists := m.policies[policy.Name]; !exists {
		return &vaulterrors.PolicyNotFoundError{Name: policy.Name}
	}

	filePath := filepath.Join(m.policiesDir, policy.Name+".yaml")
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	m.policies[policy.Name] = policy
	return nil
}

// DeletePolicy deletes a policy
func (m *Manager) DeletePolicy(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.policies[name]; !exists {
		return &vaulterrors.PolicyNotFoundError{Name: name}
	}

	filePath := filepath.Join(m.policiesDir, name+".yaml")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete policy file: %w", err)
	}

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

	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	for _, policyID := range policyIDs {
		policy, exists := m.policies[policyID]
		if !exists {
			continue
		}

		if policy.CheckPathPermission(path, capability) {
			return true
		}
	}

	return false
}

// CheckPathPermission checks if the policy grants the required capability for the path
func (p *Policy) CheckPathPermission(path string, capability Capability) bool {
	// Check for global wildcard rules
	for _, rule := range p.Rules {
		if rule.Path == "*" {
			for _, cap := range rule.Capabilities {
				if cap == capability {
					return true
				}
			}
		}
	}

	// Special case for ListCapability - match parent directories
	if capability == ListCapability {
		for _, rule := range p.Rules {
			if rule.compiledPath == nil {
				continue
			}

			if rule.compiledPath.MatchString(path) {
				for _, cap := range rule.Capabilities {
					if cap == ListCapability {
						return true
					}
				}
			}

			parentPath := path
			for parentPath != "" {
				if rule.Path == parentPath || rule.Path == parentPath+"/*" {
					for _, cap := range rule.Capabilities {
						if cap == ListCapability {
							return true
						}
					}
				}

				lastSlash := strings.LastIndex(parentPath, "/")
				if lastSlash == -1 {
					parentPath = ""
				} else {
					parentPath = parentPath[:lastSlash]
				}
			}
		}
	}

	// Check path-specific rules
	for _, rule := range p.Rules {
		if rule.compiledPath == nil {
			continue
		}

		if rule.compiledPath.MatchString(path) {
			for _, cap := range rule.Capabilities {
				if cap == capability {
					return true
				}
			}
		}
	}

	return false
}
