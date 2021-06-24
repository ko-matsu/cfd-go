package descriptor

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

type DescriptorApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *DescriptorApiImpl, err error)
	// NewDescriptorFromAddress This function return a Descriptor from pubkey.
	NewDescriptorFromPubkey(
		hashType types.HashType, pubkey *types.Pubkey) *types.Descriptor
	// NewDescriptorFromMultisig This function return a Descriptor from multisig.
	NewDescriptorFromMultisig(
		hashType types.HashType,
		pubkeys []string,
		requireNum int,
	) *types.Descriptor
	// NewDescriptor This function return a Descriptor.
	NewDescriptorFromString(descriptor string) *types.Descriptor
	// NewDescriptorFromLockingScript This function return a Descriptor from locking script.
	NewDescriptorFromLockingScript(lockingScript string) *types.Descriptor
	// NewDescriptorFromAddress This function return a Descriptor from address.
	NewDescriptorFromAddress(address string) *types.Descriptor
	// Parse This function return a Descriptor parsing data.
	Parse(descriptor *types.Descriptor) (
		data *types.DescriptorData,
		descriptorDataList []types.DescriptorData,
		multisigList []types.DescriptorKeyData,
		err error,
	)
	// ParseWithDerivationPath This function return a Descriptor parsing data.
	ParseWithDerivationPath(
		descriptor *types.Descriptor,
		bip32DerivationPath string,
	) (
		data *types.DescriptorData,
		descriptorDataList []types.DescriptorData,
		multisigList []types.DescriptorKeyData,
		err error,
	)
	// GetChecksum This function return a descriptor adding checksum.
	GetChecksum(
		descriptor *types.Descriptor) (descriptorAddedChecksum string, err error)
}

func NewDescriptorApi() *DescriptorApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := DescriptorApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network
		api.network = &network
	}
	return &api
}

// -------------------------------------
// Descriptor
// -------------------------------------

// Descriptor This struct use for the output descriptor.
type DescriptorApiImpl struct {
	// Network Type
	network *types.NetworkType
}

// WithConfig This function set a configuration.
func (p *DescriptorApiImpl) WithConfig(conf config.CfdConfig) (obj *DescriptorApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

// NewDescriptorFromAddress This function return a Descriptor from pubkey.
func (d *DescriptorApiImpl) NewDescriptorFromPubkey(hashType types.HashType, pubkey *types.Pubkey) *types.Descriptor {
	var desc string
	if hashType == types.P2shP2wpkh {
		desc = "sh(wpkh(" + pubkey.Hex + "))"
	} else if hashType == types.P2wpkh {
		desc = "wpkh(" + pubkey.Hex + ")"
	} else {
		desc = "pkh(" + pubkey.Hex + ")"
	}
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptorFromMultisig This function return a Descriptor from multisig.
func (d *DescriptorApiImpl) NewDescriptorFromMultisig(hashType types.HashType, pubkeys []string, requireNum int) *types.Descriptor {
	var desc string
	desc = desc + "multi(" + strconv.Itoa(requireNum) + "," + strings.Join(pubkeys, ",") + ")"
	if hashType == types.P2shP2wsh {
		desc = "sh(wsh(" + desc + "))"
	} else if hashType == types.P2wsh {
		desc = "wsh(" + desc + ")"
	} else if hashType == types.P2sh {
		desc = "sh(" + desc + ")"
	}
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptor This function return a Descriptor.
func (d *DescriptorApiImpl) NewDescriptorFromString(descriptor string) *types.Descriptor {
	return &types.Descriptor{
		OutputDescriptor: descriptor,
	}
}

// NewDescriptorFromLockingScript This function return a Descriptor from locking script.
func (d *DescriptorApiImpl) NewDescriptorFromLockingScript(lockingScript string) *types.Descriptor {
	desc := "raw(" + lockingScript + ")"
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptorFromAddress This function return a Descriptor from address.
func (d *DescriptorApiImpl) NewDescriptorFromAddress(address string) *types.Descriptor {
	desc := "addr(" + address + ")"
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

func (d *DescriptorApiImpl) validConfig() error {
	if d.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	}
	return nil
}

// Parse This function return a Descriptor parsing data.
func (d *DescriptorApiImpl) Parse(descriptor *types.Descriptor) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return data, descriptorDataList, multisigList, err
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.network.ToCfdValue(), "")
	if err != nil {
		return nil, nil, nil, err
	}
	return convertFromCfd(&cfdData, cfdDescDataList, cfdMultisigs)
}

// ParseWithDerivationPath This function return a Descriptor parsing data.
func (d *DescriptorApiImpl) ParseWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return data, descriptorDataList, multisigList, err
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.network.ToCfdValue(), bip32DerivationPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return convertFromCfd(&cfdData, cfdDescDataList, cfdMultisigs)
}

// GetChecksum This function return a descriptor adding checksum.
func (d *DescriptorApiImpl) GetChecksum(descriptor *types.Descriptor) (descriptorAddedChecksum string, err error) {
	if err = d.validConfig(); err != nil {
		return "", err
	}
	return cfd.CfdGoGetDescriptorChecksum(d.network.ToCfdValue(), descriptor.OutputDescriptor)
}

func convertFromCfd(cfdData *cfd.CfdDescriptorData, cfdDescriptorDataList []cfd.CfdDescriptorData, cfdMultisigList []cfd.CfdDescriptorKeyData) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	data = (*types.DescriptorData)(unsafe.Pointer(cfdData))
	descriptorDataList = *(*[]types.DescriptorData)(unsafe.Pointer(&cfdDescriptorDataList))
	multisigList = *(*[]types.DescriptorKeyData)(unsafe.Pointer(&cfdMultisigList))
	return data, descriptorDataList, multisigList, nil
}