package license

// builtinSigningSecret returns the obfuscated signing secret used to validate
// license keys. The value is XOR-decoded at runtime to prevent trivial
// extraction from the compiled binary.
func builtinSigningSecret() string {
	const xorKey = 0x5A

	obfuscated := []byte{
		50, 63, 52, 49, 59, 51, 42, 59, 52, 119, 63, 57, 60, 111, 57, 98, 60, 56, 119, 62, 62, 106, 57, 119, 110, 60, 106, 57, 119, 56, 111, 62, 104, 119, 63, 63, 63, 109, 109, 107, 99, 109, 110, 107, 59, 62,
	}

	raw := make([]byte, len(obfuscated))
	for i := range obfuscated {
		raw[i] = obfuscated[i] ^ xorKey
	}
	return string(raw)
}
