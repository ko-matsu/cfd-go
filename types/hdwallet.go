package types

// HdWallet seed
type HdWallet struct {
	Seed string
}

// ExtPrivkey xprv
type ExtPrivkey struct {
	Key string
}

type ExtkeyFormatType int

const (
	ExtkeyFormatTypeBip32 ExtkeyFormatType = 0
	ExtkeyFormatTypeBip49 ExtkeyFormatType = 1
	ExtkeyFormatTypeBip84 ExtkeyFormatType = 2
)
