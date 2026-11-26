package seal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirSplitAndCombine(t *testing.T) {
	secret := []byte("this is a 32 byte secret key!!")
	// pad to exactly 32 bytes
	for len(secret) < 32 {
		secret = append(secret, '!')
	}

	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)
	assert.Len(t, shares, 5)

	// Combine with first 3 shares
	reconstructed, err := Combine(shares[:3])
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)

	// Combine with last 3 shares
	reconstructed, err = Combine(shares[2:])
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)

	// Combine with different 3 shares
	reconstructed, err = Combine([][]byte{shares[0], shares[2], shares[4]})
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}

func TestShamirThreshold1(t *testing.T) {
	secret := []byte("simple secret with threshold one")

	shares, err := Split(secret, 3, 1)
	require.NoError(t, err)

	// Any single share should reconstruct
	for _, share := range shares {
		reconstructed, err := Combine([][]byte{share})
		require.NoError(t, err)
		assert.Equal(t, secret, reconstructed)
	}
}

func TestShamirAllShares(t *testing.T) {
	secret := []byte("all shares needed for this test!")

	shares, err := Split(secret, 5, 5)
	require.NoError(t, err)

	// Need all 5
	reconstructed, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}

func TestSealManagerLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	assert.True(t, mgr.IsSealed())
	assert.False(t, mgr.IsInitialized())

	// Initialize
	resp, err := mgr.Initialize(3, 2)
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 3)
	assert.NotEmpty(t, resp.RootToken)

	assert.False(t, mgr.IsSealed())
	assert.True(t, mgr.IsInitialized())

	// Get encryption key
	key, err := mgr.GetEncryptionKey()
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// Seal
	require.NoError(t, mgr.Seal())
	assert.True(t, mgr.IsSealed())

	// Key should not be accessible
	_, err = mgr.GetEncryptionKey()
	assert.Error(t, err)

	// Unseal with first key
	unsealed, err := mgr.SubmitUnsealKey(resp.Keys[0])
	require.NoError(t, err)
	assert.False(t, unsealed)

	// Unseal with second key
	unsealed, err = mgr.SubmitUnsealKey(resp.Keys[1])
	require.NoError(t, err)
	assert.True(t, unsealed)

	assert.False(t, mgr.IsSealed())

	// Key should be the same
	key2, err := mgr.GetEncryptionKey()
	require.NoError(t, err)
	assert.Equal(t, key, key2)
}

func TestSealManagerPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-persist-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Initialize and get keys
	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	resp, err := mgr.Initialize(2, 2)
	require.NoError(t, err)

	key1, err := mgr.GetEncryptionKey()
	require.NoError(t, err)

	// Create a new manager from the same path (simulates restart)
	mgr2 := NewManager(tmpDir)
	require.NoError(t, mgr2.LoadState())

	assert.True(t, mgr2.IsInitialized())
	assert.True(t, mgr2.IsSealed()) // Should be sealed after restart

	// Unseal with same keys
	_, err = mgr2.SubmitUnsealKey(resp.Keys[0])
	require.NoError(t, err)
	unsealed, err := mgr2.SubmitUnsealKey(resp.Keys[1])
	require.NoError(t, err)
	assert.True(t, unsealed)

	key2, err := mgr2.GetEncryptionKey()
	require.NoError(t, err)
	assert.Equal(t, key1, key2) // Same encryption key
}

func TestDoubleInitializeFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-double-init")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	_, err = mgr.Initialize(1, 1)
	require.NoError(t, err)

	_, err = mgr.Initialize(1, 1)
	assert.Error(t, err)
}

func TestInvalidUnsealKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-bad-key")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	resp, err := mgr.Initialize(1, 1)
	require.NoError(t, err)
	_ = resp

	require.NoError(t, mgr.Seal())

	// Try with a wrong key
	_, err = mgr.SubmitUnsealKey("0000000000000000000000000000000000000000000000000000000000000000ff")
	assert.Error(t, err)
}

func TestRotateShares_NewSharesUnsealSucceeds(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-rotate-success")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	_, err = mgr.Initialize(5, 3)
	require.NoError(t, err)

	keyBefore, err := mgr.GetEncryptionKey()
	require.NoError(t, err)

	rotateResp, err := mgr.RotateShares(7, 4)
	require.NoError(t, err)
	assert.Len(t, rotateResp.Keys, 7)
	assert.Equal(t, 4, rotateResp.Threshold)
	assert.Equal(t, 7, rotateResp.NumShares)

	require.NoError(t, mgr.Seal())
	assert.True(t, mgr.IsSealed())

	var unsealed bool
	for i := 0; i < 4; i++ {
		unsealed, err = mgr.SubmitUnsealKey(rotateResp.Keys[i])
		require.NoError(t, err)
	}
	assert.True(t, unsealed)
	assert.False(t, mgr.IsSealed())

	keyAfter, err := mgr.GetEncryptionKey()
	require.NoError(t, err)
	assert.Equal(t, keyBefore, keyAfter)
}

func TestRotateShares_OldSharesFailAfterRotation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-rotate-old-fail")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	initResp, err := mgr.Initialize(5, 3)
	require.NoError(t, err)
	oldKeys := initResp.Keys

	_, err = mgr.RotateShares(5, 3)
	require.NoError(t, err)

	require.NoError(t, mgr.Seal())
	assert.True(t, mgr.IsSealed())

	var lastErr error
	for i := 0; i < 3; i++ {
		_, lastErr = mgr.SubmitUnsealKey(oldKeys[i])
	}
	assert.Error(t, lastErr)
	assert.True(t, mgr.IsSealed())
}

func TestRotateShares_RequiresUnsealedVault(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-rotate-sealed")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	_, err = mgr.Initialize(3, 2)
	require.NoError(t, err)
	require.NoError(t, mgr.Seal())

	_, err = mgr.RotateShares(5, 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault is sealed")
	assert.Equal(t, 2, mgr.GetStatus().Threshold)
}

func TestRotateShares_NotInitialized(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-rotate-uninit")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	_, err = mgr.RotateShares(3, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault is not initialized")
}

func TestRotateShares_ValidatesInput(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "seal-rotate-validate")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir)
	require.NoError(t, mgr.LoadState())

	_, err = mgr.Initialize(5, 3)
	require.NoError(t, err)

	cases := []struct {
		name      string
		shares    int
		threshold int
	}{
		{"threshold greater than shares", 2, 3},
		{"threshold less than one", 3, 0},
		{"shares greater than max", 11, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mgr.RotateShares(tc.shares, tc.threshold)
			assert.Error(t, err)

			status := mgr.GetStatus()
			assert.Equal(t, 5, status.NumShares)
			assert.Equal(t, 3, status.Threshold)
		})
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	require.NoError(t, err)
	assert.True(t, len(token1) > 20)
	assert.Contains(t, token1, "s.")

	token2, err := GenerateToken()
	require.NoError(t, err)
	assert.NotEqual(t, token1, token2) // Should be unique
}

func TestGF256Arithmetic(t *testing.T) {
	// Test basic properties
	assert.Equal(t, byte(0), gf256Add(42, 42)) // x XOR x = 0
	assert.Equal(t, byte(42), gf256Add(42, 0)) // x XOR 0 = x
	assert.Equal(t, byte(0), gf256Mul(42, 0))  // x * 0 = 0
	assert.Equal(t, byte(42), gf256Mul(42, 1)) // x * 1 = x

	// Test inverse
	for i := byte(1); i != 0; i++ {
		inv := gf256Inv(i)
		assert.Equal(t, byte(1), gf256Mul(i, inv), "Failed for %d", i)
	}
}
