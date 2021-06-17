package address

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	types "github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// API
// -------------------------------------

type ConfidentialAddressApi interface {
	Create(addressString string, confidentialKey *types.Pubkey) (address *types.ConfidentialAddress, err error)
	Parse(addressString string) (address *types.ConfidentialAddress, err error)
}

func NewConfidentialAddressApi() ConfidentialAddressApi {
	return &ConfidentialAddressUtil{}
}

// -------------------------------------
// ConfidentialAddressUtil
// -------------------------------------

// ConfidentialAddressUtil ...
type ConfidentialAddressUtil struct {
}

// Create ...
func (u *ConfidentialAddressUtil) Create(addressString string, confidentialKey *types.Pubkey) (address *types.ConfidentialAddress, err error) {
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	addr := ""
	if confidentialKey != nil {
		addr, err = cfd.CfdGoCreateConfidentialAddress(addressString, confidentialKey.Hex)
		if err != nil {
			return nil, err
		}
	}
	return &types.ConfidentialAddress{
		ConfidentialAddress: addr,
		Address:             addressString,
		Network:             types.NewNetworkType(data.NetworkType),
		Type:                types.NewAddressTypeByHashType(data.HashType),
		ConfidentialKey:     confidentialKey,
	}, nil
}

// ParseAddress ...
func (u *ConfidentialAddressUtil) Parse(addressString string) (address *types.ConfidentialAddress, err error) {
	addr, key, network, err := cfd.CfdGoParseConfidentialAddress(addressString)
	if err == nil {
		data, err := cfd.CfdGoGetAddressInfo(addr)
		if err != nil {
			return nil, err
		}
		return &types.ConfidentialAddress{
			ConfidentialAddress: addressString,
			Address:             addr,
			Network:             types.NewNetworkType(network),
			Type:                types.NewAddressTypeByHashType(data.HashType),
			ConfidentialKey:     &types.Pubkey{Hex: key},
		}, nil
	}
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	return &types.ConfidentialAddress{
		Address: addressString,
		Network: types.NewNetworkType(data.NetworkType),
		Type:    types.NewAddressTypeByHashType(data.HashType),
	}, nil
}
