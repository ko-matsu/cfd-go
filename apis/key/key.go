package key

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// FIXME split file

type PubkeyApi interface {
	VerifyEcSignature(sighash, signature string) (isVerify bool, err error)
}

type PrivkeyApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *PrivkeyApiImpl, err error)
	GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error)
	GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error)
	CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error)
}

type ExtPubkeyApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *ExtPubkeyApiImpl, err error)
	GetPubkey(extPubkey *types.ExtPubkey) (pubkey *types.Pubkey, err error)
	GetData(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error)
}

type ExtPrivkeyApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *ExtPrivkeyApiImpl, err error)
	GetPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.Pubkey, err error)
	GetPrivkey(extPrivkey *types.ExtPrivkey) (privkey *types.Privkey, err error)
	GetExtPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.ExtPubkey, err error)
	GetExtPrivkeyByPath(extPrivkey *types.ExtPrivkey, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error)
	GetData(extPrivkey *types.ExtPrivkey) (data *types.ExtkeyData, err error)
}

type HdWalletApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *HdWalletApiImpl, err error)
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

func NewExtPubkeyApi() *ExtPubkeyApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := ExtPubkeyApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

func NewExtPrivkeyApi() *ExtPrivkeyApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := ExtPrivkeyApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

func NewHdWalletApiImpl() *HdWalletApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := HdWalletApiImpl{}
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

//
type ExtPubkeyApiImpl struct {
	network *types.NetworkType
}

//
type ExtPrivkeyApiImpl struct {
	network *types.NetworkType
}

//
type HdWalletApiImpl struct {
	network *types.NetworkType
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

// WithConfig This function set a configuration.
func (p *PrivkeyApiImpl) WithConfig(conf config.CfdConfig) (obj *PrivkeyApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

// GetPrivkeyFromWif ...
func (k *PrivkeyApiImpl) GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error) {
	hex, network, isCompressed, err := cfd.CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, err
	}
	networkType := types.NewNetworkType(network)
	if k.network != nil && k.network.ToBitcoinType() != networkType {
		return nil, fmt.Errorf("CFD Error: Unmatch wif network type")
	}
	return &types.Privkey{
		Wif:                wif,
		Hex:                hex,
		Network:            networkType,
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

// WithConfig This function set a configuration.
func (p *ExtPubkeyApiImpl) WithConfig(conf config.CfdConfig) (obj *ExtPubkeyApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

// GetPubkey ...
func (k *ExtPubkeyApiImpl) GetPubkey(extPubkey *types.ExtPubkey) (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(extPubkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Pubkey{Hex: hex}, nil
}

// GetData ...
func (k *ExtPubkeyApiImpl) GetData(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(extPubkey.Key)
}

// validConfig ...
func (k *ExtPubkeyApiImpl) validConfig() error {
	if k.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	} else if !k.network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

// -------------------------------------
// implement ExtPrivkey
// -------------------------------------

// WithConfig This function set a configuration.
func (p *ExtPrivkeyApiImpl) WithConfig(conf config.CfdConfig) (obj *ExtPrivkeyApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

// GetPubkey ...
func (k *ExtPrivkeyApiImpl) GetPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Pubkey{Hex: hex}, nil
}

// GetPrivkey
func (k *ExtPrivkeyApiImpl) GetPrivkey(extPrivkey *types.ExtPrivkey) (privkey *types.Privkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	hex, wif, err := cfd.CfdGoGetPrivkeyFromExtkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Privkey{
		Hex:                hex,
		Wif:                wif,
		Network:            *k.network,
		IsCompressedPubkey: true,
	}, nil
}

// GetExtPubkey
func (k *ExtPrivkeyApiImpl) GetExtPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.ExtPubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	key, err := cfd.CfdGoCreateExtPubkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.ExtPubkey{Key: key}, nil
}

func (k *ExtPrivkeyApiImpl) GetExtPrivkeyByPath(extPrivkey *types.ExtPrivkey, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	key, err := cfd.CfdGoCreateExtkeyFromParentPath(extPrivkey.Key, bip32Path, k.network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPrivkey))
	if err != nil {
		return nil, err
	}
	return &types.ExtPrivkey{Key: key}, nil
}

// GetData ...
func (k *ExtPrivkeyApiImpl) GetData(extPrivkey *types.ExtPrivkey) (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, err
	}
	return getExtkeyInformationInternal(extPrivkey.Key)
}

// validConfig ...
func (k *ExtPrivkeyApiImpl) validConfig() error {
	if k.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	} else if !k.network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

// -------------------------------------
// implement HdWalletApiImpl
// -------------------------------------

// WithConfig This function set a configuration.
func (p *HdWalletApiImpl) WithConfig(conf config.CfdConfig) (obj *HdWalletApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
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
