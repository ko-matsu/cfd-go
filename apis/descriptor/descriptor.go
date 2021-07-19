package descriptor

import (
	"strconv"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

type DescriptorApi interface {
	// GetNetworkTypes This function returns the available network types.
	GetNetworkTypes() []types.NetworkType
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

// NewDescriptorApi returns an object that defines the API for output descriptor.
func NewDescriptorApi(options ...config.CfdConfigOption) *DescriptorApiImpl {
	api := DescriptorApiImpl{}
	conf, errs := config.ConvertOptionsWithCurrentCfdConfig(options...)
	api.setError(errs)

	if !conf.Network.Valid() {
		api.setError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network
		api.network = &network
	}
	return &api
}

// -------------------------------------
// Descriptor
// -------------------------------------

// Descriptor This struct use for the output descriptor.
type DescriptorApiImpl struct {
	InitializeError error
	network         *types.NetworkType // Network Type
}

func (d *DescriptorApiImpl) setError(err error) {
	if err == nil {
		return
	}
	multiError, ok := d.InitializeError.(*cfdErrors.MultiError)
	if !ok {
		multiError = cfdErrors.NewMultiError(
			cfdErrors.CfdError("CFD Error: DescriptorApiImpl initialize error"))
	}
	multiError.Add(err)
	d.InitializeError = multiError
}

// GetNetworkTypes This function returns the available network types.
func (d *DescriptorApiImpl) GetNetworkTypes() []types.NetworkType {
	networks := []types.NetworkType{}
	if err := d.validConfig(); err != nil {
		// returns empty networks.
	} else if d.network.IsBitcoin() {
		networks = []types.NetworkType{types.Mainnet, types.Testnet, types.Regtest}
	} else if d.network.IsElements() {
		networks = []types.NetworkType{types.LiquidV1, types.ElementsRegtest}
	}
	return networks
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
		return cfdErrors.ErrNetworkConfig
	}
	return nil
}

// Parse This function return a Descriptor parsing data.
func (d *DescriptorApiImpl) Parse(descriptor *types.Descriptor) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return nil, nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.network.ToCfdValue(), "")
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parse descriptor error")
	}
	data, descriptorDataList, multisigList = convertFromCfd(&cfdData, cfdDescDataList, cfdMultisigs)
	return data, descriptorDataList, multisigList, nil
}

// ParseWithDerivationPath This function return a Descriptor parsing data.
func (d *DescriptorApiImpl) ParseWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	if err = d.validConfig(); err != nil {
		return nil, nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.network.ToCfdValue(), bip32DerivationPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parse descriptor error")
	}
	data, descriptorDataList, multisigList = convertFromCfd(&cfdData, cfdDescDataList, cfdMultisigs)
	return data, descriptorDataList, multisigList, nil
}

// GetChecksum This function return a descriptor adding checksum.
func (d *DescriptorApiImpl) GetChecksum(descriptor *types.Descriptor) (descriptorAddedChecksum string, err error) {
	if err = d.validConfig(); err != nil {
		return "", errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	descriptorAddedChecksum, err = cfd.CfdGoGetDescriptorChecksum(d.network.ToCfdValue(), descriptor.OutputDescriptor)
	if err != nil {
		return "", errors.Wrap(err, "parse descriptor error")
	}
	return descriptorAddedChecksum, nil
}

func convertFromCfd(cfdData *cfd.CfdDescriptorData, cfdDescriptorDataList []cfd.CfdDescriptorData, cfdMultisigList []cfd.CfdDescriptorKeyData) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData) {
	data = types.NewDescriptorData(cfdData)
	descriptorDataList = make([]types.DescriptorData, len(cfdDescriptorDataList))
	for i, data := range cfdDescriptorDataList {
		descriptorDataList[i] = *(types.NewDescriptorData(&data))
	}
	if cfdMultisigList != nil {
		multisigList = make([]types.DescriptorKeyData, len(cfdMultisigList))
		for i, key := range cfdMultisigList {
			multisigList[i] = types.DescriptorKeyData{
				KeyType:       key.KeyType,
				Pubkey:        key.Pubkey,
				ExtPubkey:     key.ExtPubkey,
				ExtPrivkey:    key.ExtPrivkey,
				SchnorrPubkey: key.SchnorrPubkey,
			}
		}
	}
	return data, descriptorDataList, multisigList
}
