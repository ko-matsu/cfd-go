package cfdgo

import (
	"fmt"
	"strings"
	"unsafe"
)

type NetworkType int
type AddressType int
type HashType int

const (
	// NetworkType
	Unknown NetworkType = iota
	Mainnet
	Testnet
	Regtest
	LiquidV1
	ElementsRegtest
	// AddressType
	UnknownAddress AddressType = iota
	P2pkhAddress
	P2shAddress
	P2wpkhAddress
	P2wshAddress
	P2shP2wpkhAddress
	P2shP2wshAddress
	TaprootAddress
	// HashType
	UnknownType HashType = iota
	P2pkh
	P2sh
	P2wpkh
	P2wsh
	P2shP2wpkh
	P2shP2wsh
	Taproot
)

// -------------------------------------
// API struct
// -------------------------------------

// AddressUtil ...
type AddressUtil struct {
	Network *NetworkType
}

// ConfidentialAddressUtil ...
type ConfidentialAddressUtil struct {
}

// -------------------------------------
// Data struct
// -------------------------------------

// Address ...
type Address struct {
	Address string
	Network NetworkType
	Type    AddressType
}

// ConfidentialAddress ...
type ConfidentialAddress struct {
	ConfidentialAddress string
	Address             string
	Network             NetworkType
	Type                AddressType
	ConfidentialKey     *Pubkey
}

// -------------------------------------
// NetworkType
// -------------------------------------

// NewNetworkTypeByString ...
func NewNetworkTypeByString(networkType string) NetworkType {
	switch strings.ToLower(networkType) {
	case "mainnet":
		return Mainnet
	case "testnet":
		return Testnet
	case "regtest":
		return Regtest
	case "liquidv1":
		return LiquidV1
	case "liquidv1test", "liquidregtest", "elementsregtest":
		return ElementsRegtest
	default:
		return Unknown
	}
}

// NewNetworkType ...
func NewNetworkType(cfdNetworkType int) NetworkType {
	switch cfdNetworkType {
	case int(KCfdNetworkMainnet):
		return Mainnet
	case int(KCfdNetworkTestnet):
		return Testnet
	case int(KCfdNetworkRegtest):
		return Regtest
	case int(KCfdNetworkLiquidv1):
		return LiquidV1
	case int(KCfdNetworkElementsRegtest):
		return ElementsRegtest
	default:
		return Unknown
	}
}

// ToCfdValue ...
func (n NetworkType) ToCfdValue() int {
	switch n {
	case Mainnet:
		return int(KCfdNetworkMainnet)
	case Testnet:
		return int(KCfdNetworkTestnet)
	case Regtest:
		return int(KCfdNetworkRegtest)
	case LiquidV1:
		return int(KCfdNetworkLiquidv1)
	case ElementsRegtest:
		return int(KCfdNetworkElementsRegtest)
	default:
		return int(KCfdNetworkMainnet)
	}
}

// Valid ...
func (n NetworkType) Valid() bool {
	switch n {
	case Mainnet, Testnet, Regtest, LiquidV1, ElementsRegtest:
		return true
	default:
		return false
	}
}

// IsBitcoin ...
func (n NetworkType) IsBitcoin() bool {
	switch n {
	case Mainnet, Testnet, Regtest:
		return true
	default:
		return false
	}
}

// IsElements ...
func (n NetworkType) IsElements() bool {
	switch n {
	case LiquidV1, ElementsRegtest:
		return true
	default:
		return false
	}
}

// ToBitcoinType ...
func (n NetworkType) ToBitcoinType() NetworkType {
	switch n {
	case Mainnet, Testnet, Regtest:
		return n
	case LiquidV1:
		return Mainnet
	case ElementsRegtest:
		return Regtest
	default:
		return Unknown
	}
}

// -------------------------------------
// AddressType
// -------------------------------------

// NewAddressType ...
func NewAddressType(cfdAddressType int) AddressType {
	switch cfdAddressType {
	case int(KCfdP2pkhAddress):
		return P2pkhAddress
	case int(KCfdP2shAddress):
		return P2shAddress
	case int(KCfdP2wpkhAddress):
		return P2wpkhAddress
	case int(KCfdP2wshAddress):
		return P2wshAddress
	case int(KCfdP2shP2wpkhAddress):
		return P2shP2wpkhAddress
	case int(KCfdP2shP2wshAddress):
		return P2shP2wshAddress
	case int(KCfdTaprootAddress):
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// NewAddressTypeByHashType ...
func NewAddressTypeByHashType(hashType int) AddressType {
	switch hashType {
	case int(KCfdP2pkh):
		return P2pkhAddress
	case int(KCfdP2sh):
		return P2shAddress
	case int(KCfdP2wpkh):
		return P2wpkhAddress
	case int(KCfdP2wsh):
		return P2wshAddress
	case int(KCfdP2shP2wpkh):
		return P2shP2wpkhAddress
	case int(KCfdP2shP2wsh):
		return P2shP2wshAddress
	case int(KCfdTaproot):
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// NewAddressTypeByString ...
func NewAddressTypeByString(addressType string) AddressType {
	switch strings.ToLower(addressType) {
	case "p2pkh":
		return P2pkhAddress
	case "p2sh":
		return P2shAddress
	case "p2wpkh":
		return P2wpkhAddress
	case "p2wsh":
		return P2wshAddress
	case "p2sh-p2wpkh", "p2shp2wpkh":
		return P2shP2wpkhAddress
	case "p2sh-p2wsh", "p2shp2wsh":
		return P2shP2wshAddress
	case "taproot", "p2tr":
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// ToCfdValue ...
func (n AddressType) ToCfdValue() int {
	switch n {
	case P2pkhAddress:
		return int(KCfdP2pkhAddress)
	case P2shAddress:
		return int(KCfdP2shAddress)
	case P2wpkhAddress:
		return int(KCfdP2wpkhAddress)
	case P2wshAddress:
		return int(KCfdP2wshAddress)
	case P2shP2wpkhAddress:
		return int(KCfdP2shP2wpkhAddress)
	case P2shP2wshAddress:
		return int(KCfdP2shP2wshAddress)
	case TaprootAddress:
		return int(KCfdTaprootAddress)
	default:
		return int(KCfdWitnessUnknownAddress)
	}
}

// ToHashType ...
func (n AddressType) ToHashType() HashType {
	switch n {
	case P2pkhAddress:
		return P2pkh
	case P2shAddress:
		return P2sh
	case P2wpkhAddress:
		return P2wpkh
	case P2wshAddress:
		return P2wsh
	case P2shP2wpkhAddress:
		return P2shP2wpkh
	case P2shP2wshAddress:
		return P2shP2wsh
	case TaprootAddress:
		return Taproot
	default:
		return UnknownType
	}
}

// -------------------------------------
// HashType
// -------------------------------------

// NewHashType ...
func NewHashType(cfdHashType int) HashType {
	switch cfdHashType {
	case int(KCfdP2pkh):
		return P2pkh
	case int(KCfdP2sh):
		return P2sh
	case int(KCfdP2wpkh):
		return P2wpkh
	case int(KCfdP2wsh):
		return P2wsh
	case int(KCfdP2shP2wpkh):
		return P2shP2wpkh
	case int(KCfdP2shP2wsh):
		return P2shP2wsh
	case int(KCfdTaproot):
		return Taproot
	default:
		return UnknownType
	}
}

// NewHashTypeByString ...
func NewHashTypeByString(hashType string) HashType {
	switch strings.ToLower(hashType) {
	case "p2pkh":
		return P2pkh
	case "p2sh":
		return P2sh
	case "p2wpkh":
		return P2wpkh
	case "p2wsh":
		return P2wsh
	case "p2sh-p2wpkh", "p2shp2wpkh":
		return P2shP2wpkh
	case "p2sh-p2wsh", "p2shp2wsh":
		return P2shP2wsh
	case "taproot", "p2tr":
		return Taproot
	default:
		return UnknownType
	}
}

// ToCfdValue ...
func (n HashType) ToCfdValue() int {
	switch n {
	case P2pkh:
		return int(KCfdP2pkh)
	case P2sh:
		return int(KCfdP2sh)
	case P2wpkh:
		return int(KCfdP2wpkh)
	case P2wsh:
		return int(KCfdP2wsh)
	case P2shP2wpkh:
		return int(KCfdP2shP2wpkh)
	case P2shP2wsh:
		return int(KCfdP2shP2wsh)
	case Taproot:
		return int(KCfdTaproot)
	default:
		return int(KCfdUnknown)
	}
}

// -------------------------------------
// AddressUtil
// -------------------------------------

// ParseAddress ...
func (u *AddressUtil) ParseAddress(addressString string) (address *Address, err error) {
	data, err := CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	return &Address{
		Address: addressString,
		Network: NewNetworkType(data.NetworkType),
		Type:    NewAddressTypeByHashType(data.HashType),
	}, nil
}

// CreateByPubkey ...
func (u *AddressUtil) CreateByPubkey(pubkey *Pubkey, addressType AddressType) (address *Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	addr, _, _, err := CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), pubkey.Hex, "", u.Network.ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &Address{
		Address: addr,
		Network: *u.Network,
		Type:    addressType,
	}, nil
}

// CreateByScript ...
func (u *AddressUtil) CreateByScript(redeemScript *Script, addressType AddressType) (address *Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	addr, _, _, err := CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), "", redeemScript.ToHex(), u.Network.ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &Address{
		Address: addr,
		Network: *u.Network,
		Type:    addressType,
	}, nil
}

// CreateMultisigAddress ...
func (u *AddressUtil) CreateMultisigAddress(pubkeys *[]Pubkey, requireNum uint32, addressType AddressType) (address *Address, redeemScript *Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	}
	pubkeyList := make([]string, len(*pubkeys))
	for i := 0; i < len(*pubkeys); i++ {
		pubkeyList[i] = (*pubkeys)[i].Hex
	}
	addr, script, witnessScript, err := CfdGoCreateMultisigScript(u.Network.ToCfdValue(), addressType.ToHashType().ToCfdValue(), pubkeyList, requireNum)
	if err != nil {
		return nil, nil, err
	}
	if addressType == P2shAddress {
		redeemScript = &Script{hex: script}
	} else {
		redeemScript = &Script{hex: witnessScript}
	}
	return &Address{
		Address: addr,
		Network: *u.Network,
		Type:    addressType,
	}, redeemScript, nil
}

// GetPeginAddressByPubkey ...
func (u *AddressUtil) GetPeginAddressByPubkey(addressType AddressType, fedpegScript, pubkey string) (peginAddress *Address, claimScript *Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	}

	addr, script, _, err := GetPeginAddress(u.Network.ToBitcoinType().ToCfdValue(), fedpegScript, addressType.ToCfdValue(), pubkey, "")
	if err != nil {
		return nil, nil, err
	}
	peginAddress = &Address{
		Address: addr,
		Network: u.Network.ToBitcoinType(),
		Type:    addressType,
	}
	claimScript = &Script{
		hex: script,
	}
	return peginAddress, claimScript, nil
}

// GetPegoutAddress ...
func (u *AddressUtil) GetPegoutAddress(addressType AddressType, descriptorOrXpub string, bip32Counter uint32) (pegoutAddress *Address, baseDescriptor *string, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, err
	}

	addr, desc, err := GetPegoutAddress(u.Network.ToBitcoinType().ToCfdValue(), u.Network.ToCfdValue(), descriptorOrXpub, bip32Counter, addressType.ToCfdValue())
	if err != nil {
		return nil, nil, err
	}
	pegoutAddress = &Address{
		Address: addr,
		Network: u.Network.ToBitcoinType(),
		Type:    addressType,
	}
	baseDescriptor = &desc
	return pegoutAddress, baseDescriptor, nil
}

// validConfig ...
func (u *AddressUtil) validConfig() error {
	if u.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		netType := cfdConfig.Network
		u.Network = &netType
	}
	return nil
}

// -------------------------------------
// ConfidentialAddressUtil
// -------------------------------------

// Create ...
func (u *ConfidentialAddressUtil) Create(addressString string, confidentialKey *Pubkey) (address *ConfidentialAddress, err error) {
	data, err := CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	addr := ""
	if confidentialKey != nil {
		addr, err = CfdGoCreateConfidentialAddress(addressString, confidentialKey.Hex)
		if err != nil {
			return nil, err
		}
	}
	return &ConfidentialAddress{
		ConfidentialAddress: addr,
		Address:             addressString,
		Network:             NewNetworkType(data.NetworkType),
		Type:                NewAddressTypeByHashType(data.HashType),
		ConfidentialKey:     confidentialKey,
	}, nil
}

// ParseAddress ...
func (u *ConfidentialAddressUtil) Parse(addressString string) (address *ConfidentialAddress, err error) {
	addr, key, network, err := CfdGoParseConfidentialAddress(addressString)
	if err == nil {
		data, err := CfdGoGetAddressInfo(addr)
		if err != nil {
			return nil, err
		}
		return &ConfidentialAddress{
			ConfidentialAddress: addressString,
			Address:             addr,
			Network:             NewNetworkType(network),
			Type:                NewAddressTypeByHashType(data.HashType),
			ConfidentialKey:     &Pubkey{Hex: key},
		}, nil
	}
	data, err := CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, err
	}
	return &ConfidentialAddress{
		Address: addressString,
		Network: NewNetworkType(data.NetworkType),
		Type:    NewAddressTypeByHashType(data.HashType),
	}, nil
}

// low-layer API ---------------------------------------------------------------

// GetPeginAddress This function get a pegin address.
func GetPeginAddress(mainchainNetworkType int, fedpegScript string, hashType int, pubkey, redeemScript string) (peginAddress, claimScript, tweakedFedpegScript string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPeginAddress(handle, mainchainNetworkType, fedpegScript,
		hashType, pubkey, redeemScript, &peginAddress, &claimScript, &tweakedFedpegScript)
	err = convertCfdError(ret, handle)
	return
}

// GetPegoutAddress This function get a pegout address.
func GetPegoutAddress(mainchainNetworkType, elementsNetworkType int, descriptorOrXpub string, bip32Counter uint32, addressType int) (pegoutAddress, baseDescriptor string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	bip32CounterPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&bip32Counter)))
	ret := CfdGetPegoutAddress(handle, mainchainNetworkType, elementsNetworkType, descriptorOrXpub, bip32CounterPtr, addressType, &pegoutAddress, &baseDescriptor)
	err = convertCfdError(ret, handle)
	return
}
