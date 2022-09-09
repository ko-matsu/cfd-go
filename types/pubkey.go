package types

const (
	CompressedPubkeyLength      = 33  // compressed pubkey length
	CompressedPubkeyHexLength   = 66  // compressed pubkey hex length
	UncompressedPubkeyLength    = 65  // uncompressed pubkey length
	UncompressedPubkeyHexLength = 130 // uncompressed pubkey hex length
)

// Pubkey ...
type Pubkey struct {
	Hex string
}
