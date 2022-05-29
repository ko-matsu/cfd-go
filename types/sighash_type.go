package types

import (
	"strings"

	cfdgo "github.com/cryptogarageinc/cfd-go"
)

// SigHashType This struct use for the sighashtype utility function.
type SigHashType struct {
	Type         int
	AnyoneCanPay bool
	Rangeproof   bool
}

// NewSigHashType This function return a SigHashType.
func NewSigHashType(sighashType int) *SigHashType {
	value := sighashType & 0x0f
	anyoneCanPay := false
	isRangeproof := false
	if (sighashType & 0x80) != 0 {
		anyoneCanPay = true
	}
	if (sighashType & 0x40) != 0 {
		isRangeproof = true
	}
	return &SigHashType{
		Type:         value,
		AnyoneCanPay: anyoneCanPay,
		Rangeproof:   isRangeproof,
	}
}

// NewSigHashTypeFromString return a SigHashType.
func NewSigHashTypeFromString(sighashType string) *SigHashType {
	var sighashTypes []string
	if strings.Contains(sighashType, "|") {
		sighashTypes = strings.Split(sighashType, "|")
	} else {
		sighashTypes = strings.Split(sighashType, "+")
	}
	anyoneCanPay := false
	isRangeproof := false
	var value int

	for i, typeStr := range sighashTypes {
		typeStr = strings.ToLower(typeStr)
		if i == 0 {
			switch typeStr {
			case "default":
				value = 0
			case "all":
				value = 1
			case "none":
				value = 2
			case "single":
				value = 3
			default:
				panic("invalid sighash type: " + sighashType)
			}
		} else {
			switch typeStr {
			case "anyonecanpay":
				anyoneCanPay = true
			case "rangeproof":
				isRangeproof = true
			default:
				panic("invalid sighash type: " + sighashType)
			}
		}
	}

	return &SigHashType{
		Type:         value,
		AnyoneCanPay: anyoneCanPay,
		Rangeproof:   isRangeproof,
	}
}

// ToHex This function return a sighashtype byte value.
func (obj *SigHashType) GetValue() int {
	value := obj.Type
	if (value & 0x80) != 0 {
		// do nothing
	} else if obj.AnyoneCanPay {
		value |= 0x80
	}
	if (value & 0x40) != 0 {
		// do nothing
	} else if obj.Rangeproof {
		value |= 0x40
	}
	return value
}

// String ...
func (obj *SigHashType) String() string {
	val := obj.GetValue()
	low := val & 0x0f
	high := val & 0xf0

	var result string
	switch low {
	case 0:
		return "default"
	case 1:
		result = "all"
	case 2:
		result = "none"
	case 3:
		result = "single"
	default:
		return "unknown"
	}

	if (high & 0x80) != 0 {
		result += "+anyonecanpay"
	}
	if (high & 0x40) != 0 {
		result += "+rangeproof"
	}
	return result
}

func (obj *SigHashType) ToCfdValue() *cfdgo.SigHashType {
	return &cfdgo.SigHashType{
		Type:         obj.Type,
		AnyoneCanPay: obj.AnyoneCanPay,
		Rangeproof:   obj.Rangeproof,
	}
}

var SigHashTypeDefault SigHashType = *NewSigHashType(0)
var SigHashTypeAll SigHashType = *NewSigHashType(1)
var SigHashTypeNone SigHashType = *NewSigHashType(2)
var SigHashTypeSingle SigHashType = *NewSigHashType(3)
