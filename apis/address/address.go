package address

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	config "github.com/cryptogarageinc/cfd-go/config"
	types "github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// API
// -------------------------------------

type AddressApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *AddressApiImpl, err error)
	ParseAddress(addressString string) (address *types.Address, err error)
	CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error)
	CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error)
	CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error)
	GetPeginAddressByPubkey(addressType types.AddressType, fedpegScript, pubkey string) (peginAddress *types.Address, claimScript *types.Script, err error)
	GetPegoutAddress(addressType types.AddressType, descriptorOrXpub string, bip32Counter uint32) (pegoutAddress *types.Address, baseDescriptor *string, err error)
}

func NewAddressApi() *AddressApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := AddressApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network
		api.network = &network
	}
	return &api
}

// -------------------------------------
// AddressApiImpl
// -------------------------------------

// AddressApiImpl ...
type AddressApiImpl struct {
	network *types.NetworkType
}

// WithConfig This function set a configuration.
func (p *AddressApiImpl) WithConfig(conf config.CfdConfig) (obj *AddressApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network
	p.network = &network
	return p, nil
}

// ParseAddress ...
func (u *AddressApiImpl) ParseAddress(addressString string) (address *types.Address, err error) {
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	return &types.Address{
		Address: addressString,
		Network: types.NewNetworkType(data.NetworkType),
		Type:    types.NewAddressTypeByHashType(data.HashType),
	}, nil
}

// CreateByPubkey ...
func (u *AddressApiImpl) CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), pubkey.Hex, "", u.network.ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}, nil
}

// CreateByScript ...
func (u *AddressApiImpl) CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), "", redeemScript.ToHex(), u.network.ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}, nil
}

// CreateMultisigAddress ...
func (u *AddressApiImpl) CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	}
	pubkeyList := make([]string, len(*pubkeys))
	for i := 0; i < len(*pubkeys); i++ {
		pubkeyList[i] = (*pubkeys)[i].Hex
	}
	addr, script, witnessScript, err := cfd.CfdGoCreateMultisigScript(u.network.ToCfdValue(), addressType.ToHashType().ToCfdValue(), pubkeyList, requireNum)
	if err != nil {
		return nil, nil, err
	}
	if addressType == types.P2shAddress {
		redeemScript = types.NewScriptFromHexIgnoreError(script)
	} else {
		redeemScript = types.NewScriptFromHexIgnoreError(witnessScript)
	}
	return &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}, redeemScript, nil
}

// GetPeginAddressByPubkey ...
func (u *AddressApiImpl) GetPeginAddressByPubkey(addressType types.AddressType, fedpegScript, pubkey string) (peginAddress *types.Address, claimScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	}

	addr, script, _, err := cfd.GetPeginAddress(u.network.ToBitcoinType().ToCfdValue(), fedpegScript, addressType.ToCfdValue(), pubkey, "")
	if err != nil {
		return nil, nil, err
	}
	peginAddress = &types.Address{
		Address: addr,
		Network: u.network.ToBitcoinType(),
		Type:    addressType,
	}
	claimScript = types.NewScriptFromHexIgnoreError(script)
	return peginAddress, claimScript, nil
}

// GetPegoutAddress ...
func (u *AddressApiImpl) GetPegoutAddress(addressType types.AddressType, descriptorOrXpub string, bip32Counter uint32) (pegoutAddress *types.Address, baseDescriptor *string, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	} else if !u.network.IsElements() {
		return nil, nil, fmt.Errorf("CFD Error: GetPegoutAddress need elements network type")
	}

	addr, desc, err := cfd.GetPegoutAddress(u.network.ToBitcoinType().ToCfdValue(), u.network.ToCfdValue(), descriptorOrXpub, bip32Counter, addressType.ToCfdValue())
	if err != nil {
		return nil, nil, err
	}
	pegoutAddress = &types.Address{
		Address: addr,
		Network: u.network.ToBitcoinType(),
		Type:    addressType,
	}
	baseDescriptor = &desc
	return pegoutAddress, baseDescriptor, nil
}

// validConfig ...
func (u *AddressApiImpl) validConfig() error {
	if u.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	}
	return nil
}
