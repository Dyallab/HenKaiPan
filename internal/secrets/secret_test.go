package secrets

import (
	"testing"

	"aspm/internal/assert"
)

func TestMain(m *testing.M) {
	SetKey("test-encryption-key-32bytes!")
	m.Run()
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	original := "my-sensitive-value"
	enc, err := Encrypt(original)
	assert.NoError(t, err)
	assert.NotEqual(t, enc, original) // must be different
	assert.True(t, len(enc) > 0)

	dec, err := Decrypt(enc)
	assert.NoError(t, err)
	assert.Equal(t, dec, original)
}

func TestEncryptDecrypt_WithSpaces(t *testing.T) {
	original := "  value-with-spaces  "
	enc, err := Encrypt(original)
	assert.NoError(t, err)
	dec, err := Decrypt(enc)
	assert.NoError(t, err)
	assert.Equal(t, dec, "value-with-spaces") // trimmed
}

func TestEncrypt_Empty(t *testing.T) {
	result, err := Encrypt("")
	assert.NoError(t, err)
	assert.Equal(t, result, "")
}

func TestDecrypt_Empty(t *testing.T) {
	result, err := Decrypt("")
	assert.NoError(t, err)
	assert.Equal(t, result, "")
}

func TestDecrypt_Unencrypted(t *testing.T) {
	// Values without the "enc:v1:" prefix are returned as-is
	result, err := Decrypt("plain-text-value")
	assert.NoError(t, err)
	assert.Equal(t, result, "plain-text-value")
}

func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	_, err := Decrypt("enc:v1:not-valid-base64!!!")
	assert.True(t, err != nil) // should return some error (not nil)
}

func TestDecrypt_WrongKey(t *testing.T) {
	original := "secret-value"
	enc, err := Encrypt(original)
	assert.NoError(t, err)

	// Change key and try to decrypt
	SetKey("different-key-for-test!")
	_, err = Decrypt(enc)
	assert.True(t, err != nil) // should fail with wrong key

	// Restore key for subsequent tests
	SetKey("test-encryption-key-32bytes!")
}

func TestDecrypt_ShortCiphertext(t *testing.T) {
	_, err := Decrypt("enc:v1:c2hvcnQ=")
	assert.True(t, err != nil)
}
