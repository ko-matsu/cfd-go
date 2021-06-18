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

// -------------------------------------
// Descriptor
// -------------------------------------

// Descriptor This struct use for the output descriptor.
type DescriptorApiImpl struct {
	// Network Type
	Network *types.NetworkType
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
	if d.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		netType := cfdConfig.Network
		d.Network = &netType
	}
	return nil
}

// Parse This function return a Descriptor parsing data.
func (d *DescriptorApiImpl) Parse(descriptor *types.Descriptor) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return data, descriptorDataList, multisigList, err
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.Network.ToCfdValue(), "")
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
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.Network.ToCfdValue(), bip32DerivationPath)
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
	return cfd.CfdGoGetDescriptorChecksum(d.Network.ToCfdValue(), descriptor.OutputDescriptor)
}

func convertFromCfd(cfdData *cfd.CfdDescriptorData, cfdDescriptorDataList []cfd.CfdDescriptorData, cfdMultisigList []cfd.CfdDescriptorKeyData) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	data = (*types.DescriptorData)(unsafe.Pointer(cfdData))
	descriptorDataList = *(*[]types.DescriptorData)(unsafe.Pointer(&cfdDescriptorDataList))
	multisigList = *(*[]types.DescriptorKeyData)(unsafe.Pointer(&cfdMultisigList))
	return data, descriptorDataList, multisigList, nil
}
