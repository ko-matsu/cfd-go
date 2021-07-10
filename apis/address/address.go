package address

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	config "github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

// -------------------------------------
// API
// -------------------------------------

// AddressApi This interface handles bitcoin addresses.
type AddressApi interface {
	ParseAddress(addressString string) (address *types.Address, err error)
	CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error)
	CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error)
	CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error)
}

// ElementsAddressApi This interface handles elements addresses.
type ElementsAddressApi interface {
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
		return p, cfdErrors.NetworkConfigError
	}
	network := conf.Network
	p.network = &network
	return p, nil
}

// ParseAddress ...
func (u *AddressApiImpl) ParseAddress(addressString string) (address *types.Address, err error) {
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, errors.Wrap(err, "parse address error")
	}
	address = &types.Address{
		Address: addressString,
		Network: types.NewNetworkType(data.NetworkType),
		Type:    types.NewAddressTypeByHashType(data.HashType),
	}
	return address, nil
}

// CreateByPubkey ...
func (u *AddressApiImpl) CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), pubkey.Hex, "", u.network.ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create address error")
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, nil
}

// CreateByScript ...
func (u *AddressApiImpl) CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), "", redeemScript.ToHex(), u.network.ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create address error")
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, nil
}

// CreateMultisigAddress ...
func (u *AddressApiImpl) CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	pubkeyList := make([]string, len(*pubkeys))
	for i := 0; i < len(*pubkeys); i++ {
		pubkeyList[i] = (*pubkeys)[i].Hex
	}
	addr, script, witnessScript, err := cfd.CfdGoCreateMultisigScript(u.network.ToCfdValue(), addressType.ToHashType().ToCfdValue(), pubkeyList, requireNum)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create multisig error")
	}
	if addressType == types.P2shAddress {
		redeemScript = types.NewScriptFromHexIgnoreError(script)
	} else {
		redeemScript = types.NewScriptFromHexIgnoreError(witnessScript)
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, redeemScript, nil
}

// GetPeginAddressByPubkey ...
func (u *AddressApiImpl) GetPeginAddressByPubkey(addressType types.AddressType, fedpegScript, pubkey string) (peginAddress *types.Address, claimScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	addr, script, _, err := cfd.GetPeginAddress(u.network.ToBitcoinType().ToCfdValue(), fedpegScript, addressType.ToCfdValue(), pubkey, "")
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegin address error")
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
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if !u.network.IsElements() {
		return nil, nil, errors.Errorf("CFD Error: GetPegoutAddress need elements network type")
	}

	addr, desc, err := cfd.GetPegoutAddress(u.network.ToBitcoinType().ToCfdValue(), u.network.ToCfdValue(), descriptorOrXpub, bip32Counter, addressType.ToCfdValue())
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegout address error")
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
		return cfdErrors.NetworkConfigError
	}
	return nil
}
