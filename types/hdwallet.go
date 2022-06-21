package types

import "strings"

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
	ExtkeyFormatTypeUnknown ExtkeyFormatType = -1
	ExtkeyFormatTypeBip32   ExtkeyFormatType = 0
	ExtkeyFormatTypeBip49   ExtkeyFormatType = 1
	ExtkeyFormatTypeBip84   ExtkeyFormatType = 2
)

func NewExtkeyFormatTypeByString(formatTypeStr string) ExtkeyFormatType {
	switch strings.ToLower(formatTypeStr) {
	case "bip32", "normal":
		return ExtkeyFormatTypeBip32
	case "bip49":
		return ExtkeyFormatTypeBip49
	case "bip84":
		return ExtkeyFormatTypeBip84
	default:
		return ExtkeyFormatTypeUnknown
	}
}

func (t ExtkeyFormatType) ToCfdValue() int {
	return int(t)
}
