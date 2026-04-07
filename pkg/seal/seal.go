package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
)

// SealConfig holds the configuration for the seal mechanism
type SealConfig struct {
	// SecretShares is the number of shares to split the master key into
	SecretShares int `yaml:"secret_shares" json:"secret_shares"`
	// SecretThreshold is the minimum number of shares needed to unseal
	SecretThreshold int `yaml:"secret_threshold" json:"secret_threshold"`
}

// InitResponse is returned when the vault is first initialized
type InitResponse struct {
	// Keys are the unseal key shares (hex-encoded)
	Keys []string `json:"keys"`
	// RootToken is the initial root token
	RootToken string `json:"root_token"`
}

// SealStatus represents the current seal status
type SealStatus struct {
	Sealed      bool   `json:"sealed"`
	Threshold   int    `json:"threshold"`
	NumShares   int    `json:"num_shares"`
	Progress    int    `json:"progress"`
	Initialized bool   `json:"initialized"`
	ClusterName string `json:"cluster_name,omitempty"`
}

// Manager manages the seal/unseal lifecycle
type Manager struct {
	mu              sync.RWMutex
	sealed          bool
	initialized     bool
	masterKey       []byte
	encryptionKey   []byte // derived from master key, used to encrypt data
	threshold       int
	numShares       int
	unsealProgress  [][]byte // key shares submitted so far
	sealDataPath    string   // path to persist encrypted seal data
}

// sealData is persisted to disk - contains the encrypted master key info
type sealData struct {
	// EncryptedMasterKey is the master key encrypted with itself (for validation)
	MasterKeyHash  string `json:"master_key_hash"`
	Threshold      int    `json:"threshold"`
	NumShares      int    `json:"num_shares"`
	// EncryptedEncKey is the encryption key encrypted with the master key
	EncryptedEncKey string `json:"encrypted_enc_key"`
	// Nonce used for encrypting the encryption key
	EncKeyNonce string `json:"enc_key_nonce"`
}

// NewManager creates a new seal manager
func NewManager(dataPath string) *Manager {
	return &Manager{
		sealed:       true,
		initialized:  false,
		sealDataPath: dataPath,
	}
}

// LoadState checks if the vault has been previously initialized
func (m *Manager) LoadState() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sealPath := m.getSealFilePath()
	if _, err := os.Stat(sealPath); err == nil {
		m.initialized = true
		// Load seal data to get threshold/shares info
		data, err := os.ReadFile(sealPath)
		if err != nil {
			return fmt.Errorf("failed to read seal data: %w", err)
		}
		var sd sealData
		if err := json.Unmarshal(data, &sd); err != nil {
			return fmt.Errorf("failed to parse seal data: %w", err)
		}
		m.threshold = sd.Threshold
		m.numShares = sd.NumShares
	}
	return nil
}

func (m *Manager) getSealFilePath() string {
	return m.sealDataPath + "/seal.json"
}

// Initialize sets up the vault for the first time, generating the master key
// and splitting it into shares using Shamir's Secret Sharing
func (m *Manager) Initialize(shares, threshold int) (*InitResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil, errors.New("vault is already initialized")
	}

	if threshold < 1 {
		return nil, errors.New("threshold must be at least 1")
	}
	if shares < threshold {
		return nil, errors.New("shares must be >= threshold")
	}
	if shares > 10 {
		return nil, errors.New("maximum of 10 shares supported")
	}

	// Generate master key (32 bytes for AES-256)
	masterKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Generate a separate encryption key (the master key is used to protect this)
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Split master key using Shamir's Secret Sharing
	keyShares, err := Split(masterKey, shares, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split master key: %w", err)
	}

	// Encrypt the encryption key with the master key
	encryptedEncKey, nonce, err := encryptWithKey(masterKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt encryption key: %w", err)
	}

	// Hash the master key for later validation
	hash := sha256.Sum256(masterKey)

	// Persist seal data
	sd := sealData{
		MasterKeyHash:   hex.EncodeToString(hash[:]),
		Threshold:       threshold,
		NumShares:       shares,
		EncryptedEncKey: hex.EncodeToString(encryptedEncKey),
		EncKeyNonce:     hex.EncodeToString(nonce),
	}

	sdBytes, err := json.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal seal data: %w", err)
	}

	if err := os.MkdirAll(m.sealDataPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create seal data directory: %w", err)
	}

	if err := os.WriteFile(m.getSealFilePath(), sdBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write seal data: %w", err)
	}

	// Generate root token
	rootTokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rootTokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate root token: %w", err)
	}
	rootToken := "s." + hex.EncodeToString(rootTokenBytes)

	// Set state
	m.initialized = true
	m.sealed = false
	m.masterKey = masterKey
	m.encryptionKey = encryptionKey
	m.threshold = threshold
	m.numShares = shares
	m.unsealProgress = nil

	// Hex-encode shares for the response
	hexKeys := make([]string, len(keyShares))
	for i, share := range keyShares {
		hexKeys[i] = hex.EncodeToString(share)
	}

	return &InitResponse{
		Keys:      hexKeys,
		RootToken: rootToken,
	}, nil
}

// SubmitUnsealKey submits a key share for unsealing
// Returns true if the vault is now unsealed
func (m *Manager) SubmitUnsealKey(keyHex string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return false, errors.New("vault is not initialized")
	}

	if !m.sealed {
		return false, errors.New("vault is already unsealed")
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, fmt.Errorf("invalid key format: %w", err)
	}

	// Add to progress
	m.unsealProgress = append(m.unsealProgress, keyBytes)

	// Check if we have enough shares
	if len(m.unsealProgress) < m.threshold {
		return false, nil
	}

	// Attempt to reconstruct master key
	masterKey, err := Combine(m.unsealProgress)
	if err != nil {
		m.unsealProgress = nil // Reset on failure
		return false, fmt.Errorf("failed to reconstruct master key: %w", err)
	}

	// Validate the reconstructed key
	hash := sha256.Sum256(masterKey)
	expectedHash, err := m.getExpectedHash()
	if err != nil {
		m.unsealProgress = nil
		return false, err
	}

	if hex.EncodeToString(hash[:]) != expectedHash {
		m.unsealProgress = nil
		return false, errors.New("invalid unseal keys: master key reconstruction failed")
	}

	// Decrypt the encryption key
	encryptionKey, err := m.decryptEncryptionKey(masterKey)
	if err != nil {
		m.unsealProgress = nil
		return false, fmt.Errorf("failed to decrypt encryption key: %w", err)
	}

	// Success - unseal
	m.masterKey = masterKey
	m.encryptionKey = encryptionKey
	m.sealed = false
	m.unsealProgress = nil

	return true, nil
}

// Seal seals the vault
func (m *Manager) Seal() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return errors.New("vault is not initialized")
	}

	if m.sealed {
		return errors.New("vault is already sealed")
	}

	// Clear sensitive material from memory
	for i := range m.masterKey {
		m.masterKey[i] = 0
	}
	for i := range m.encryptionKey {
		m.encryptionKey[i] = 0
	}
	m.masterKey = nil
	m.encryptionKey = nil
	m.sealed = true
	m.unsealProgress = nil

	return nil
}

// IsSealed returns whether the vault is sealed
func (m *Manager) IsSealed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sealed
}

// IsInitialized returns whether the vault has been initialized
func (m *Manager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initialized
}

// GetEncryptionKey returns the encryption key (only when unsealed)
func (m *Manager) GetEncryptionKey() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.sealed {
		return nil, errors.New("vault is sealed")
	}

	key := make([]byte, len(m.encryptionKey))
	copy(key, m.encryptionKey)
	return key, nil
}

// GetStatus returns the current seal status
func (m *Manager) GetStatus() SealStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return SealStatus{
		Sealed:      m.sealed,
		Threshold:   m.threshold,
		NumShares:   m.numShares,
		Progress:    len(m.unsealProgress),
		Initialized: m.initialized,
	}
}

func (m *Manager) getExpectedHash() (string, error) {
	data, err := os.ReadFile(m.getSealFilePath())
	if err != nil {
		return "", fmt.Errorf("failed to read seal data: %w", err)
	}
	var sd sealData
	if err := json.Unmarshal(data, &sd); err != nil {
		return "", fmt.Errorf("failed to parse seal data: %w", err)
	}
	return sd.MasterKeyHash, nil
}

func (m *Manager) decryptEncryptionKey(masterKey []byte) ([]byte, error) {
	data, err := os.ReadFile(m.getSealFilePath())
	if err != nil {
		return nil, fmt.Errorf("failed to read seal data: %w", err)
	}
	var sd sealData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("failed to parse seal data: %w", err)
	}

	encryptedEncKey, err := hex.DecodeString(sd.EncryptedEncKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	nonce, err := hex.DecodeString(sd.EncKeyNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return decryptWithKey(masterKey, encryptedEncKey, nonce)
}

// encryptWithKey encrypts data with a key using AES-256-GCM
func encryptWithKey(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decryptWithKey decrypts data with a key using AES-256-GCM
func decryptWithKey(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// --- Shamir's Secret Sharing ---
// Uses GF(256) arithmetic for byte-level secret sharing

// prime is a large prime for the finite field (we use GF(2^8) with polynomial operations)
// For simplicity and security, we operate on each byte independently using GF(256)

const shareOverhead = 1 // 1 byte for the x-coordinate

// Split splits a secret into n shares with a threshold of t
func Split(secret []byte, n, t int) ([][]byte, error) {
	if t < 1 {
		return nil, errors.New("threshold must be at least 1")
	}
	if n < t {
		return nil, errors.New("number of shares must be >= threshold")
	}
	if n > 255 {
		return nil, errors.New("number of shares must be <= 255")
	}

	// Create shares: each share is [x-coordinate | share-bytes...]
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+shareOverhead)
		shares[i][0] = byte(i + 1) // x-coordinates are 1..n (0 is reserved for the secret)
	}

	// For each byte of the secret, create a random polynomial and evaluate
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// Create a polynomial with the secret byte as the constant term
		// and random coefficients for higher-order terms
		coeffs := make([]byte, t)
		coeffs[0] = secret[byteIdx]

		// Generate random coefficients for terms 1..t-1
		if t > 1 {
			randomCoeffs := make([]byte, t-1)
			if _, err := io.ReadFull(rand.Reader, randomCoeffs); err != nil {
				return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
			}
			copy(coeffs[1:], randomCoeffs)
		}

		// Evaluate the polynomial at each x-coordinate
		for i := 0; i < n; i++ {
			x := shares[i][0]
			shares[i][byteIdx+shareOverhead] = evalPolynomial(coeffs, x)
		}
	}

	return shares, nil
}

// Combine reconstructs a secret from shares using Lagrange interpolation
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 1 {
		return nil, errors.New("need at least one share")
	}

	// Verify all shares have the same length
	shareLen := len(shares[0])
	for _, share := range shares {
		if len(share) != shareLen {
			return nil, errors.New("shares have inconsistent lengths")
		}
	}

	secretLen := shareLen - shareOverhead
	secret := make([]byte, secretLen)

	// Extract x-coordinates
	xCoords := make([]byte, len(shares))
	for i, share := range shares {
		xCoords[i] = share[0]
	}

	// For each byte position, perform Lagrange interpolation at x=0
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		yCoords := make([]byte, len(shares))
		for i, share := range shares {
			yCoords[i] = share[byteIdx+shareOverhead]
		}

		secret[byteIdx] = lagrangeInterpolate(xCoords, yCoords)
	}

	return secret, nil
}

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

// gf256Add adds two elements in GF(256) (XOR)
func gf256Add(a, b byte) byte {
	return a ^ b
}

// gf256Mul multiplies two elements in GF(256)
func gf256Mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

// gf256Inv computes the multiplicative inverse in GF(256) using extended Euclidean algorithm
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0 // undefined, but handle gracefully
	}
	// Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
	// Since the field has 256 elements, the multiplicative group has order 255
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result)
		result = gf256Mul(result, a)
	}
	// One more squaring gives a^254
	result = gf256Mul(result, result)
	return result
}

// gf256Div divides a by b in GF(256)
func gf256Div(a, b byte) byte {
	return gf256Mul(a, gf256Inv(b))
}

// evalPolynomial evaluates a polynomial in GF(256)
func evalPolynomial(coeffs []byte, x byte) byte {
	// Horner's method
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gf256Add(gf256Mul(result, x), coeffs[i])
	}
	return result
}

// lagrangeInterpolate performs Lagrange interpolation at x=0 in GF(256)
func lagrangeInterpolate(xCoords, yCoords []byte) byte {
	n := len(xCoords)
	var result byte

	for i := 0; i < n; i++ {
		// Compute the Lagrange basis polynomial evaluated at 0
		var basis byte = 1
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			// basis *= (0 - x_j) / (x_i - x_j) = x_j / (x_i - x_j) in GF(256)
			// Note: in GF(256), subtraction is XOR (same as addition)
			num := xCoords[j]                                // 0 XOR x_j = x_j
			denom := gf256Add(xCoords[i], xCoords[j])       // x_i XOR x_j
			basis = gf256Mul(basis, gf256Div(num, denom))
		}

		result = gf256Add(result, gf256Mul(yCoords[i], basis))
	}

	return result
}

// --- Utility for generating secure tokens ---

// GenerateToken generates a cryptographically secure token
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return "s." + hex.EncodeToString(b), nil
}

// GenerateNonce generates a random nonce of the specified size
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// DeriveKey derives a key from a master key and a purpose string using SHA-256
func DeriveKey(masterKey []byte, purpose string) []byte {
	h := sha256.New()
	h.Write(masterKey)
	h.Write([]byte(purpose))
	derived := h.Sum(nil)
	return derived
}

// --- Big integer helpers for validation ---

// bigFromBytes creates a big.Int from a byte slice
func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
