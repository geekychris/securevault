package vaulterrors

import (
	"errors"
	"fmt"
)

// Sentinel errors for the vault system
var (
	// ErrNotFound indicates the requested resource was not found
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates the resource already exists
	ErrAlreadyExists = errors.New("already exists")

	// ErrSealed indicates the vault is sealed and cannot process requests
	ErrSealed = errors.New("vault is sealed")

	// ErrInvalidToken indicates the provided token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied")

	// ErrVersionNotFound indicates the requested version does not exist
	ErrVersionNotFound = errors.New("version not found")

	// ErrVersionDestroyed indicates the requested version has been destroyed
	ErrVersionDestroyed = errors.New("version destroyed")

	// ErrInvalidRequest indicates the request is malformed
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInternal indicates an internal server error
	ErrInternal = errors.New("internal error")
)

// SecretNotFoundError wraps ErrNotFound with a path
type SecretNotFoundError struct {
	Path string
}

func (e *SecretNotFoundError) Error() string {
	return fmt.Sprintf("secret not found: %s", e.Path)
}

func (e *SecretNotFoundError) Unwrap() error {
	return ErrNotFound
}

// PolicyNotFoundError wraps ErrNotFound with a policy name
type PolicyNotFoundError struct {
	Name string
}

func (e *PolicyNotFoundError) Error() string {
	return fmt.Sprintf("policy not found: %s", e.Name)
}

func (e *PolicyNotFoundError) Unwrap() error {
	return ErrNotFound
}

// PolicyExistsError wraps ErrAlreadyExists with a policy name
type PolicyExistsError struct {
	Name string
}

func (e *PolicyExistsError) Error() string {
	return fmt.Sprintf("policy already exists: %s", e.Name)
}

func (e *PolicyExistsError) Unwrap() error {
	return ErrAlreadyExists
}

// VersionNotFoundError wraps ErrVersionNotFound with path and version
type VersionNotFoundError struct {
	Path    string
	Version int
}

func (e *VersionNotFoundError) Error() string {
	return fmt.Sprintf("version %d not found for secret %s", e.Version, e.Path)
}

func (e *VersionNotFoundError) Unwrap() error {
	return ErrVersionNotFound
}

// VersionDestroyedError wraps ErrVersionDestroyed with path and version
type VersionDestroyedError struct {
	Path    string
	Version int
}

func (e *VersionDestroyedError) Error() string {
	return fmt.Sprintf("version %d of secret %s has been destroyed", e.Version, e.Path)
}

func (e *VersionDestroyedError) Unwrap() error {
	return ErrVersionDestroyed
}

// IsNotFound checks if an error is a not-found error
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsAlreadyExists checks if an error is an already-exists error
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

// IsSealed checks if an error is a sealed error
func IsSealed(err error) bool {
	return errors.Is(err, ErrSealed)
}

// IsVersionNotFound checks if an error is a version-not-found error
func IsVersionNotFound(err error) bool {
	return errors.Is(err, ErrVersionNotFound)
}

// IsVersionDestroyed checks if an error is a version-destroyed error
func IsVersionDestroyed(err error) bool {
	return errors.Is(err, ErrVersionDestroyed)
}
