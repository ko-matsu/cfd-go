package key

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// PubkeyApi This interface has pubkey operation API.
type PubkeyApi interface {
	VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error)
}

// PrivkeyApi This interface has privkey operation API.
type PrivkeyApi interface {
	GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error)
	GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error)
	CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error)
}

func NewPubkeyApi() *PubkeyApiImpl {
	return &PubkeyApiImpl{}
}

func NewPrivkeyApi() *PrivkeyApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := PrivkeyApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

// -------------------------------------
// struct
// -------------------------------------

//
type PubkeyApiImpl struct {
}

//
type PrivkeyApiImpl struct {
	network *types.NetworkType
}

// -------------------------------------
// implement Pubkey
// -------------------------------------

// VerifyEcSignature ...
func (p *PubkeyApiImpl) VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error) {
	isVerify, err = cfd.CfdGoVerifyEcSignature(sighash, pubkey.Hex, signature)
	return isVerify, err
}

// -------------------------------------
// implement Privkey
// -------------------------------------

// WithConfig This function set a configuration.
func (p *PrivkeyApiImpl) WithConfig(conf config.CfdConfig) (obj *PrivkeyApiImpl, err error) {
	obj = p
	if !conf.Network.Valid() {
		err = fmt.Errorf("CFD Error: Invalid network configuration")
		return obj, err
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return obj, nil
}

// GetPrivkeyFromWif ...
func (k *PrivkeyApiImpl) GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error) {
	hex, network, isCompressed, err := cfd.CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, err
	}
	networkType := types.NewNetworkType(network)
	if (k.network != nil) && !isMatchNetworkType(k.network.ToBitcoinType(), networkType) {
		err = fmt.Errorf("CFD Error: Unmatch wif network type")
		return nil, err
	}
	privkey = &types.Privkey{
		Wif:                wif,
		Hex:                hex,
		Network:            networkType,
		IsCompressedPubkey: isCompressed,
	}
	return privkey, nil
}

// GetPubkey ...
func (k *PrivkeyApiImpl) GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error) {
	hex, err := cfd.CfdGoGetPubkeyFromPrivkey(privkey.Hex, "", privkey.IsCompressedPubkey)
	if err != nil {
		return nil, err
	}
	pubkey = &types.Pubkey{Hex: hex}
	return pubkey, nil
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
	signature = types.NewByteDataFromHexIgnoreError(derSig)
	return signature, nil
}

// -------------------------------------
// internal
// -------------------------------------

func isMatchNetworkType(keyNetwork types.NetworkType, network types.NetworkType) bool {
	if keyNetwork == network {
		return true
	} else if (keyNetwork == types.Regtest) && (network == types.Testnet) {
		return true
	} else if (keyNetwork == types.Testnet) && (network == types.Regtest) {
		return true
	} else {
		return false
	}
}
