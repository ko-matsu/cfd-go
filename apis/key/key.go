package key

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
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
	CreateEcSignatureGrindR(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType, grindR bool) (signature *types.ByteData, err error)
}

func NewPubkeyApi() *PubkeyApiImpl {
	return &PubkeyApiImpl{}
}

func NewPrivkeyApi(options ...config.CfdConfigOption) *PrivkeyApiImpl {
	api := PrivkeyApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network.ToBitcoinType()
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
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

// -------------------------------------
// implement Pubkey
// -------------------------------------

// VerifyEcSignature ...
func (p *PubkeyApiImpl) VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error) {
	isVerify, err = cfd.CfdGoVerifyEcSignature(sighash, pubkey.Hex, signature)
	if err != nil {
		return false, errors.Wrap(err, "verify ec signature error")
	}
	return isVerify, nil
}

// -------------------------------------
// implement Privkey
// -------------------------------------

// GetPrivkeyFromWif ...
func (k *PrivkeyApiImpl) GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error) {
	hex, network, isCompressed, err := cfd.CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, errors.Wrap(err, "parse wif error")
	}
	networkType := types.NewNetworkType(network)
	if (k.network != nil) && (k.network.ToBitcoinType().IsMainnet() != networkType.IsMainnet()) {
		err = errors.Errorf("CFD Error: Unmatch wif network type")
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
		return nil, errors.Wrap(err, "get pubkey error")
	}
	pubkey = &types.Pubkey{Hex: hex}
	return pubkey, nil
}

// CreateEcSignature ...
func (k *PrivkeyApiImpl) CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error) {
	return k.CreateEcSignatureGrindR(privkey, sighash, sighashType, true)
}

// CreateEcSignatureGrindR ...
func (k *PrivkeyApiImpl) CreateEcSignatureGrindR(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType, grindR bool) (signature *types.ByteData, err error) {
	sig, err := cfd.CfdGoCalculateEcSignature(sighash.ToHex(), privkey.Hex, privkey.Wif, privkey.Network.ToCfdValue(), grindR)
	if err != nil {
		return nil, errors.Wrap(err, "calculate ec signature error")
	}
	if sighashType == nil {
		return types.NewByteDataFromHexIgnoreError(sig), nil
	}
	// DER encode
	derSig, err := cfd.CfdGoEncodeSignatureByDer(sig, sighashType.GetValue(), sighashType.AnyoneCanPay)
	if err != nil {
		return nil, errors.Wrap(err, "DER encode error")
	}
	signature = types.NewByteDataFromHexIgnoreError(derSig)
	return signature, nil
}
