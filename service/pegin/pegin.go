package pegin

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// wrap and validation APIs
type Pegin interface {
	// GetPubkeyFromExtPubkey ...
	GetPubkeyFromExtPubkey(
		extPubkey *types.ExtPubkey,
		bip32Path string,
	) (
		pubkey *types.Pubkey,
		derivedExtPubkey *types.ExtPubkey,
		err error,
	)
	// CreatePeginAddress ...
	CreatePeginAddress(
		addressType types.AddressType,
		extPubkey *types.ExtPubkey,
		bip32Path string,
		fedpegScript *types.Script,
	) (
		peginAddress *types.Address,
		claimScript *types.Script,
		pubkey *types.Pubkey,
		err error,
	)
	// CreatePeginTransaction ...
	CreatePeginTransaction(
		peginOutPoint *types.OutPoint,
		peginData *types.InputPeginData,
		utxoList *[]types.ElementsUtxoData,
		sendList []types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.FundRawTxOption,
	) (tx *types.ConfidentialTx, err error)
	// VerifyPubkeySignature
	VerifyPubkeySignature(
		proposalTx *types.Transaction,
		utxoList *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
	// VerifyPeginPubkeySignature
	VerifyPeginPubkeySignature(
		proposalTx *types.Transaction,
		extPubkey *types.ExtPubkey,
		bip32Path string,
		signature *types.ByteData,
	) (isVerify bool, err error)
}

func NewPeginService() *PeginService {
	return &PeginService{}
}

// -------------------------------------
// PeginUtil
// -------------------------------------

type PeginService struct {
	Network *types.NetworkType
}

func (p *PeginService) validConfig() error {
	if p.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		netType := cfdConfig.Network
		p.Network = &netType
	}
	if !p.Network.IsElements() {
		return fmt.Errorf("CFD Error: NetworkType is not elements")
	}
	return nil
}

func (p *PeginService) GetPubkeyFromExtPubkey(
	extPubkey *types.ExtPubkey,
	bip32Path string,
) (
	pubkey *types.Pubkey,
	derivedExtPubkey *types.ExtPubkey,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, err
	}
	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, p.Network.ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, err
	}
	pubkeyHex, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.Network.ToCfdValue())
	if err != nil {
		return nil, nil, err
	}
	return &types.Pubkey{Hex: pubkeyHex}, &types.ExtPubkey{Key: deriveKey}, nil
}

func (p *PeginService) CreatePeginAddress(
	addressType types.AddressType,
	extPubkey *types.ExtPubkey,
	bip32Path string,
	fedpegScript *types.Script,
) (
	peginAddress *types.Address,
	claimScript *types.Script,
	pubkey *types.Pubkey,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, nil, err
	}
	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, p.Network.ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, nil, err
	}
	pubkeyHex, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.Network.ToCfdValue())
	if err != nil {
		return nil, nil, nil, err
	}
	addrApi := address.NewAddressApi()
	peginAddress, claimScript, err = addrApi.GetPeginAddressByPubkey(addressType, fedpegScript.ToHex(), pubkeyHex)
	if err != nil {
		return nil, nil, nil, err
	}
	return peginAddress, claimScript, &types.Pubkey{Hex: pubkeyHex}, nil
}

func (p *PeginService) CreatePeginTransaction(
	peginOutPoint *types.OutPoint,
	peginData *types.InputPeginData,
	utxoList *[]types.ElementsUtxoData,
	sendList []types.InputConfidentialTxOut,
	changeAddress *string,
	option *types.FundRawTxOption,
) (tx *types.ConfidentialTx, err error) {
	// FIXME implements
	// 1. create transaction
	// 2. add txout by output if single output.
	// 3. fundrawtransaction
	// 4. blind
	return nil, nil
}

func (p *PeginService) VerifyPubkeySignature(
	proposalTx *types.Transaction,
	utxoList *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	// 1. pegin: auto-get amount etc.
	// 2. other utxo: normal verify
	return false, nil
}

func (p *PeginService) VerifyPeginPubkeySignature(
	proposalTx *types.Transaction,
	extPubkey *types.ExtPubkey,
	bip32Path string,
	signature *types.ByteData,
) (isVerify bool, err error) {
	// 1. pegin: auto-get amount etc.
	return false, nil
}
