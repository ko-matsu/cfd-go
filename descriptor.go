package cfdgo

import (
	"fmt"
	"strconv"
	"strings"
)

// -------------------------------------
// Descriptor
// -------------------------------------

// Descriptor This struct use for the output descriptor.
type Descriptor struct {
	// Output Descriptor
	OutputDescriptor string
	// Network Type
	Network *NetworkType
}

// NewDescriptorFromAddress This function return a Descriptor from pubkey.
func NewDescriptorFromPubkey(hashType int, pubkey string, networkType int) *Descriptor {
	var desc string
	if hashType == (int)(KCfdP2shP2wpkh) {
		desc = "sh(wpkh(" + pubkey + "))"
	} else if hashType == (int)(KCfdP2wpkh) {
		desc = "wpkh(" + pubkey + ")"
	} else {
		desc = "pkh(" + pubkey + ")"
	}
	netType := NewNetworkType(networkType)
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          &netType,
	}
}

// NewDescriptorFromMultisig This function return a Descriptor from multisig.
func NewDescriptorFromMultisig(hashType int, pubkeys []string, requireNum, networkType int) *Descriptor {
	var desc string
	desc = desc + "multi(" + strconv.Itoa(requireNum) + "," + strings.Join(pubkeys, ",") + ")"
	if hashType == (int)(KCfdP2shP2wsh) {
		desc = "sh(wsh(" + desc + "))"
	} else if hashType == (int)(KCfdP2wsh) {
		desc = "wsh(" + desc + ")"
	} else if hashType == (int)(KCfdP2sh) {
		desc = "sh(" + desc + ")"
	}
	netType := NewNetworkType(networkType)
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          &netType,
	}
}

// NewDescriptor This function return a Descriptor.
func NewDescriptorFromString(descriptor string, networkType int) *Descriptor {
	netType := NewNetworkType(networkType)
	return &Descriptor{
		OutputDescriptor: descriptor,
		Network:          &netType,
	}
}

// NewDescriptorFromLockingScript This function return a Descriptor from locking script.
func NewDescriptorFromLockingScript(lockingScript string, networkType int) *Descriptor {
	desc := "raw(" + lockingScript + ")"
	netType := NewNetworkType(networkType)
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          &netType,
	}
}

// NewDescriptorFromAddress This function return a Descriptor from address.
func NewDescriptorFromAddress(address string, networkType int) *Descriptor {
	desc := "addr(" + address + ")"
	netType := NewNetworkType(networkType)
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          &netType,
	}
}

func (d *Descriptor) validConfig() error {
	if d.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		netType := cfdConfig.Network
		d.Network = &netType
	}
	return nil
}

// Parse This function return a Descriptor parsing data.
func (d *Descriptor) Parse() (data DescriptorData, descriptorDataList []DescriptorData, multisigList []DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return data, descriptorDataList, multisigList, err
	}
	return CfdGoParseDescriptorData(d.OutputDescriptor, d.Network.ToCfdValue(), "")
}

// ParseWithDerivationPath This function return a Descriptor parsing data.
func (d *Descriptor) ParseWithDerivationPath(bip32DerivationPath string) (data DescriptorData, descriptorDataList []DescriptorData, multisigList []DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return data, descriptorDataList, multisigList, err
	}
	return CfdGoParseDescriptorData(d.OutputDescriptor, d.Network.ToCfdValue(), bip32DerivationPath)
}

// GetChecksum This function return a descriptor adding checksum.
func (d *Descriptor) GetChecksum() (descriptorAddedChecksum string, err error) {
	if err = d.validConfig(); err != nil {
		return "", err
	}
	return CfdGoGetDescriptorChecksum(d.Network.ToCfdValue(), d.OutputDescriptor)
}
