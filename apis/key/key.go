package key

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// struct
// -------------------------------------

type PubkeyApi interface {
	VerifyEcSignature(sighash, signature string) (isVerify bool, err error)
}

//
type PubkeyApiImpl struct {
}

//
type PrivkeyApiImpl struct {
}

func NewPrivkeyApi() *PrivkeyApiImpl {
	return &PrivkeyApiImpl{}
}

//
type HdWalletApiImpl struct {
	Network *types.NetworkType
}

// ExtPrivkey xpriv
type ExtPrivkey struct {
	Key     string
	Network *types.NetworkType
}

// -------------------------------------
// implement Pubkey
// -------------------------------------

// VerifyEcSignature ...
func (p *PubkeyApiImpl) VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error) {
	return cfd.CfdGoVerifyEcSignature(sighash, pubkey.Hex, signature)
}

// -------------------------------------
// implement Privkey
// -------------------------------------

// NewPrivkeyFromWif ...
func NewPrivkeyFromWif(wif string) (privkey *types.Privkey, err error) {
	hex, network, isCompressed, err := cfd.CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, err
	}
	return &types.Privkey{
		Wif:                wif,
		Hex:                hex,
		Network:            types.NewNetworkType(network),
		IsCompressedPubkey: isCompressed,
	}, nil
}

// GetPubkey ...
func (k *PrivkeyApiImpl) GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error) {
	hex, err := cfd.CfdGoGetPubkeyFromPrivkey(privkey.Hex, "", privkey.IsCompressedPubkey)
	if err != nil {
		return nil, err
	}
	return &types.Pubkey{Hex: hex}, nil
}

// CreateEcSignature ...
func (k *PrivkeyApiImpl) CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error) {
	sig, err := cfd.CfdGoCalculateEcSignature(sighash.ToHex(), privkey.Hex, "", privkey.Network.ToCfdValue(), true)
	if err != nil {
		return nil, err
	}
	if sighashType == nil {
		return types.NewByteDataFromHexIgnoreError(sig), nil
	}
	// DER encode
	derSig, err := cfd.CfdGoEncodeSignatureByDer(sig, sighashType.GetValue(), sighashType.AnyoneCanPay)
	if err != nil {
		return nil, err
	}
	return types.NewByteDataFromHexIgnoreError(derSig), nil
}

// -------------------------------------
// implement ExtPubkey
// -------------------------------------

// validConfig ...
func (k *HdWalletApiImpl) validConfig() error {
	if k.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		network := cfdConfig.Network.ToBitcoinType()
		k.Network = &network
	}
	return nil
}

// GetPubkey ...
func (k *HdWalletApiImpl) GetPubkey(extPubkey *types.ExtPubkey) (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(extPubkey.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Pubkey{Hex: hex}, nil
}

// GetData ...
func (k *HdWalletApiImpl) GetData(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(extPubkey.Key)
}

// -------------------------------------
// implement ExtPrivkey
// -------------------------------------

// validConfig ...
func (k *ExtPrivkey) validConfig() error {
	if k.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		network := cfdConfig.Network.ToBitcoinType()
		k.Network = &network
	}
	return nil
}

// GetPubkey ...
func (k *ExtPrivkey) GetPubkey() (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Pubkey{Hex: hex}, nil
}

// GetPrivkey
func (k *ExtPrivkey) GetPrivkey() (privkey *types.Privkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, wif, err := cfd.CfdGoGetPrivkeyFromExtkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Privkey{
		Hex:                hex,
		Wif:                wif,
		Network:            *k.Network,
		IsCompressedPubkey: true,
	}, nil
}

// GetPrivkey
func (k *ExtPrivkey) GetExtPubkey() (pubkey *types.ExtPubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	key, err := cfd.CfdGoCreateExtPubkey(k.Key, k.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.ExtPubkey{Key: key}, nil
}

// GetData ...
func (k *ExtPrivkey) GetData() (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(k.Key)
}

// internal --------------------------------------------------------------------

func getExtkeyInformationInternal(key string) (data *types.ExtkeyData, err error) {
	tempData, err := cfd.CfdGoGetExtkeyInformation(key)
	if err != nil {
		return nil, err
	}
	return &types.ExtkeyData{
		Version:     tempData.Version,
		Fingerprint: tempData.Fingerprint,
		Depth:       tempData.Depth,
		ChildNumber: tempData.ChildNumber,
		ChainCode:   tempData.ChainCode,
	}, nil
}
