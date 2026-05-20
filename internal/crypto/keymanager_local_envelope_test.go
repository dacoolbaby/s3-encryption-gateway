package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalEnvelopeKeyManager_Conformance(t *testing.T) {
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		t.Helper()
		km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
		require.NoError(t, err)
		return km
	})
}

func TestLocalEnvelopeKeyManager_WrapUnwrap(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	assert.Equal(t, localEnvelopeKMProvider, env.Provider)
	assert.NotEmpty(t, env.Ciphertext)
	assert.Equal(t, 1, env.KeyVersion)

	// Ciphertext must not embed the plaintext DEK.
	for i := 0; i+len(dek) <= len(env.Ciphertext); i++ {
		assert.NotEqual(t, dek, env.Ciphertext[i:i+len(dek)], "ciphertext must not embed plaintext DEK at offset %d", i)
	}

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestLocalEnvelopeKeyManager_DifferentNoncePerWrap(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()

	env1, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	env2, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	assert.NotEqual(t, env1.Ciphertext, env2.Ciphertext, "two wraps must produce distinct ciphertexts")
}

func TestLocalEnvelopeKeyManager_WrongPassword(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	km2, err := NewLocalEnvelopeKeyManager([]byte("totally-different-password!!"), DefaultPBKDF2Iterations)
	require.NoError(t, err)
	_, err = km2.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

func TestLocalEnvelopeKeyManager_TamperedCiphertext(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	// Flip the last byte (part of the GCM tag).
	tampered := make([]byte, len(env.Ciphertext))
	copy(tampered, env.Ciphertext)
	tampered[len(tampered)-1] ^= 0xff
	env.Ciphertext = tampered

	_, err = km.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

func TestLocalEnvelopeKeyManager_Close(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	ctx := context.Background()

	// Close should be idempotent.
	assert.NoError(t, km.Close(ctx))
	assert.NoError(t, km.Close(ctx))

	// Post-close operations fail.
	_, err = km.WrapKey(ctx, make([]byte, 32), nil)
	assert.ErrorIs(t, err, ErrProviderUnavailable)

	_, err = km.UnwrapKey(ctx, &KeyEnvelope{Provider: localEnvelopeKMProvider, Ciphertext: make([]byte, 28)}, nil)
	assert.ErrorIs(t, err, ErrProviderUnavailable)

	_, err = km.ActiveKeyVersion(ctx)
	assert.ErrorIs(t, err, ErrProviderUnavailable)

	assert.ErrorIs(t, km.HealthCheck(ctx), ErrProviderUnavailable)
}

func TestLocalEnvelopeKeyManager_ShortPassword(t *testing.T) {
	_, err := NewLocalEnvelopeKeyManager([]byte("short"), DefaultPBKDF2Iterations)
	require.Error(t, err)
}

func TestLocalEnvelopeKeyManager_DefaultIterations(t *testing.T) {
	// Below-minimum iterations should be upgraded to default.
	km, err := NewLocalEnvelopeKeyManager(testPassword, 1)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestLocalEnvelopeKeyManager_ProviderMismatch(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	env := &KeyEnvelope{Provider: "cosmian-kmip", Ciphertext: []byte{1, 2, 3}}
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
}

func TestLocalEnvelopeKeyManager_InvalidEnvelope(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = km.UnwrapKey(ctx, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	_, err = km.UnwrapKey(ctx, &KeyEnvelope{Provider: localEnvelopeKMProvider}, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestLocalEnvelopeKeyManager_CiphertextSize(t *testing.T) {
	km, err := NewLocalEnvelopeKeyManager(testPassword, DefaultPBKDF2Iterations)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	// Expected: nonce(12) + DEK(32) + tag(16) = 60 bytes
	expectedSize := 12 + 32 + 16
	assert.Len(t, env.Ciphertext, expectedSize,
		"ciphertext should be nonce(%d) + DEK(%d) + tag(%d) = %d bytes",
		12, 32, 16, expectedSize)
}
