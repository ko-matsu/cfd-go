package types

import (
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
)

type HashType int

const (
	// HashType
	UnknownType HashType = iota
	P2pkh
	P2sh
	P2wpkh
	P2wsh
	P2shP2wpkh
	P2shP2wsh
	Taproot
)

// NewHashType ...
func NewHashType(cfdHashType int) HashType {
	switch cfdHashType {
	case int(cfd.KCfdP2pkh):
		return P2pkh
	case int(cfd.KCfdP2sh):
		return P2sh
	case int(cfd.KCfdP2wpkh):
		return P2wpkh
	case int(cfd.KCfdP2wsh):
		return P2wsh
	case int(cfd.KCfdP2shP2wpkh):
		return P2shP2wpkh
	case int(cfd.KCfdP2shP2wsh):
		return P2shP2wsh
	case int(cfd.KCfdTaproot):
		return Taproot
	default:
		return UnknownType
	}
}

// NewHashTypeByString ...
func NewHashTypeByString(hashType string) HashType {
	switch strings.ToLower(hashType) {
	case "p2pkh":
		return P2pkh
	case "p2sh":
		return P2sh
	case "p2wpkh":
		return P2wpkh
	case "p2wsh":
		return P2wsh
	case "p2sh-p2wpkh", "p2shp2wpkh":
		return P2shP2wpkh
	case "p2sh-p2wsh", "p2shp2wsh":
		return P2shP2wsh
	case "taproot", "p2tr":
		return Taproot
	default:
		return UnknownType
	}
}

// ToCfdValue ...
func (n HashType) ToCfdValue() int {
	switch n {
	case P2pkh:
		return int(cfd.KCfdP2pkh)
	case P2sh:
		return int(cfd.KCfdP2sh)
	case P2wpkh:
		return int(cfd.KCfdP2wpkh)
	case P2wsh:
		return int(cfd.KCfdP2wsh)
	case P2shP2wpkh:
		return int(cfd.KCfdP2shP2wpkh)
	case P2shP2wsh:
		return int(cfd.KCfdP2shP2wsh)
	case Taproot:
		return int(cfd.KCfdTaproot)
	default:
		return int(cfd.KCfdUnknown)
	}
}
