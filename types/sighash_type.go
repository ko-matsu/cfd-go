package types


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

var SigHashTypeDefault SigHashType = *NewSigHashType(0)
var SigHashTypeAll SigHashType = *NewSigHashType(1)
var SigHashTypeNone SigHashType = *NewSigHashType(2)
var SigHashTypeSingle SigHashType = *NewSigHashType(3)

