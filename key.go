package cfdgo

import "fmt"

// -------------------------------------
// struct
// -------------------------------------

// Pubkey ...
type Pubkey struct {
	Hex string
}

type PubkeyApi interface {
	VerifyEcSignature(sighash, signature string) (isVerify bool, err error)
}

// Privkey ...
type Privkey struct {
	Hex                string
	Wif                string
	Network            NetworkType
	IsCompressedPubkey bool
}

// ExtPubkey xpub
type ExtPubkey struct {
	Key     string
	Network *NetworkType
}

// ExtPrivkey xpriv
type ExtPrivkey struct {
	Key     string
	Network *NetworkType
}

type ExtkeyData struct {
	// version
	Version string
	// parent fingerprint
	Fingerprint string
	// chain code
	ChainCode string
	// depth
	Depth uint32
	// child number
	ChildNumber uint32
}

// -------------------------------------
// implement Pubkey
// -------------------------------------

// VerifyEcSignature ...
func (p *Pubkey) VerifyEcSignature(sighash, signature string) (isVerify bool, err error) {
	return CfdGoVerifyEcSignature(sighash, p.Hex, signature)
}

// -------------------------------------
// implement Privkey
// -------------------------------------

// NewPrivkeyFromWif ...
func NewPrivkeyFromWif(wif string) (privkey *Privkey, err error) {
	hex, network, isCompressed, err := CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, err
	}
	return &Privkey{
		Wif:                wif,
		Hex:                hex,
		Network:            NewNetworkType(network),
		IsCompressedPubkey: isCompressed,
	}, nil
}

// GetPubkey ...
func (k *Privkey) GetPubkey() (pubkey *Pubkey, err error) {
	hex, err := CfdGoGetPubkeyFromPrivkey(k.Hex, "", k.IsCompressedPubkey)
	if err != nil {
		return nil, err
	}
	return &Pubkey{Hex: hex}, nil
}

// CreateEcSignature ...
func (k *Privkey) CreateEcSignature(sighash *ByteData, sighashType *SigHashType) (signature *ByteData, err error) {
	sig, err := CfdGoCalculateEcSignature(sighash.ToHex(), k.Hex, "", k.Network.ToCfdValue(), true)
	if err != nil {
		return nil, err
	}
	if sighashType == nil {
		return NewByteDataFromHexIgnoreError(sig), nil
	}
	// DER encode
	derSig, err := CfdGoEncodeSignatureByDer(sig, sighashType.GetValue(), sighashType.AnyoneCanPay)
	if err != nil {
		return nil, err
	}
	return NewByteDataFromHexIgnoreError(derSig), nil
}

// -------------------------------------
// implement ExtPubkey
// -------------------------------------

// validConfig ...
func (k *ExtPubkey) validConfig() error {
	if k.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		network := cfdConfig.Network.ToBitcoinType()
		k.Network = &network
	}
	return nil
}

// GetPubkey ...
func (k *ExtPubkey) GetPubkey() (pubkey *Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := CfdGoGetPubkeyFromExtkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &Pubkey{Hex: hex}, nil
}

// GetData ...
func (k *ExtPubkey) GetData() (data *ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(k.Key)
}

// -------------------------------------
// implement ExtPrivkey
// -------------------------------------

// validConfig ...
func (k *ExtPrivkey) validConfig() error {
	if k.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		network := cfdConfig.Network.ToBitcoinType()
		k.Network = &network
	}
	return nil
}

// GetPubkey ...
func (k *ExtPrivkey) GetPubkey() (pubkey *Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := CfdGoGetPubkeyFromExtkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &Pubkey{Hex: hex}, nil
}

// GetPrivkey
func (k *ExtPrivkey) GetPrivkey() (privkey *Privkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, wif, err := CfdGoGetPrivkeyFromExtkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &Privkey{
		Hex:                hex,
		Wif:                wif,
		Network:            *k.Network,
		IsCompressedPubkey: true,
	}, nil
}

// GetPrivkey
func (k *ExtPrivkey) GetExtPubkey() (pubkey *ExtPubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	key, err := CfdGoCreateExtPubkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &ExtPubkey{Key: key}, nil
}

// GetData ...
func (k *ExtPrivkey) GetData() (data *ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(k.Key)
}

// internal --------------------------------------------------------------------

func getExtkeyInformationInternal(key string) (data *ExtkeyData, err error) {
	tempData, err := CfdGoGetExtkeyInformation(key)
	if err != nil {
		return nil, err
	}
	return &ExtkeyData{
		Version:     tempData.Version,
		Fingerprint: tempData.Fingerprint,
		Depth:       tempData.Depth,
		ChildNumber: tempData.ChildNumber,
		ChainCode:   tempData.ChainCode,
	}, nil
}
