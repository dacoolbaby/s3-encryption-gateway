package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"
)

// localEnvelopeKMProvider is the Provider() string for local envelope key wrapping.
const localEnvelopeKMProvider = "local-envelope"

// localEnvelopeKMFixedSalt is used as the PBKDF2 salt for deriving the master
// key from the password.  Using a fixed salt means the same password always
// produces the same master key, which is safe because the master key only wraps
// per-object random DEKs — the same model used by MinIO SSE-S3.
const localEnvelopeKMFixedSalt = "local-envelope-v1"

// localEnvelopeKeyManager implements KeyManager using a one-time PBKDF2
// derivation at startup to produce a master key, then AES-256-GCM for
// per-object DEK wrapping/unwrapping.
//
// This replaces PasswordKeyManager for performance: PBKDF2 runs once at startup
// instead of per-request (~45ms saving per wrap/unwrap).
//
// Ciphertext format:
//
//	nonce(12) || sealed(DEK + tag(16))
//
// Total ~60 bytes for a 32-byte DEK.
type localEnvelopeKeyManager struct {
	mu       sync.Mutex
	masterAEAD cipher.AEAD
	closed   bool
}

// NewLocalEnvelopeKeyManager creates a KeyManager that derives a master key
// once via PBKDF2-SHA256 and then uses AES-256-GCM for per-object DEK wrapping.
//
// password must be at least 12 characters.  pbkdf2Iterations controls the
// one-time cost paid at startup; defaults to DefaultPBKDF2Iterations if below
// MinPBKDF2Iterations.
func NewLocalEnvelopeKeyManager(password []byte, pbkdf2Iterations int) (KeyManager, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("local_envelope_keymanager: password must be at least 12 characters")
	}
	if pbkdf2Iterations < MinPBKDF2Iterations {
		pbkdf2Iterations = DefaultPBKDF2Iterations
	}

	// Derive the master key once.  Fixed salt means the same password always
	// produces the same key; security relies on per-object random DEKs.
	masterKey, err := pbkdf2.Key(sha256.New, string(password), []byte(localEnvelopeKMFixedSalt), pbkdf2Iterations, aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("local_envelope_keymanager: derive master key: %w", err)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("local_envelope_keymanager: create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("local_envelope_keymanager: create GCM: %w", err)
	}

	// Zero the derived key bytes; the AEAD holds the key internally.
	zeroBytes(masterKey)

	return &localEnvelopeKeyManager{masterAEAD: aead}, nil
}

func (m *localEnvelopeKeyManager) Provider() string { return localEnvelopeKMProvider }

// WrapKey encrypts plaintext with the pre-derived master key using AES-GCM.
func (m *localEnvelopeKeyManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("local_envelope_keymanager: plaintext DEK must not be empty")
	}

	nonce := make([]byte, m.masterAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("local_envelope_keymanager: generate nonce: %w", err)
	}

	sealed := m.masterAEAD.Seal(nil, nonce, plaintext, nil)

	// Ciphertext format: [nonce][sealed(DEK+tag)]
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return &KeyEnvelope{
		Provider:   localEnvelopeKMProvider,
		KeyVersion: 1,
		Ciphertext: payload,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// UnwrapKey decrypts an envelope produced by WrapKey.
func (m *localEnvelopeKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if envelope == nil || len(envelope.Ciphertext) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if envelope.Provider != localEnvelopeKMProvider {
		return nil, fmt.Errorf("local_envelope_keymanager: envelope provider mismatch (got %q, want %q)", envelope.Provider, localEnvelopeKMProvider)
	}

	payload := envelope.Ciphertext
	nonceSize := m.masterAEAD.NonceSize()

	// Minimum: nonce(12) + tag(16) = 28 bytes
	if len(payload) < nonceSize+tagSize {
		return nil, fmt.Errorf("%w: payload too short (%d bytes)", ErrInvalidEnvelope, len(payload))
	}

	nonce := payload[:nonceSize]
	sealed := payload[nonceSize:]

	plaintext, err := m.masterAEAD.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, err)
	}
	return plaintext, nil
}

func (m *localEnvelopeKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return 1, nil
}

func (m *localEnvelopeKeyManager) HealthCheck(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	return nil
}

func (m *localEnvelopeKeyManager) Close(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.masterAEAD = nil
	}
	return nil
}
