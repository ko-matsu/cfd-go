package types

const (
	PrivkeyLength    = 32 // privkey length
	PrivkeyHexLength = 64 // privkey hex length
)

// Privkey ...
type Privkey struct {
	Hex                string
	Wif                string
	Network            NetworkType
	IsCompressedPubkey bool
}
