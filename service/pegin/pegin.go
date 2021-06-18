package pegin

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// Pegin This interface defines the API used by the pegin function.
type Pegin interface {
	// GetPubkeyFromExtPubkey This function get the pubkey from xpubkey.
	GetPubkeyFromExtPubkey(
		extPubkey *types.ExtPubkey,
		bip32Path string,
	) (
		pubkey *types.Pubkey,
		derivedExtPubkey *types.ExtPubkey,
		err error,
	)
	// CreatePeginAddress This function get the pegin address and claim script.
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
	// CreatePeginTransaction This function create the pegin claim transaction.
	CreatePeginTransaction(
		peginOutPoint *types.OutPoint,
		peginData *types.InputPeginData,
		utxoList *[]types.ElementsUtxoData,
		sendList []types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.FundRawTxOption,
	) (tx *types.ConfidentialTx, err error)
	// VerifyPubkeySignature This function validate the signature by pubkey.
	VerifyPubkeySignature(
		proposalTx *types.Transaction,
		utxoList *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
	// VerifyPubkeySignature This function validate the pegin signature by pubkey.
	VerifyPeginPubkeySignature(
		proposalTx *types.Transaction,
		extPubkey *types.ExtPubkey,
		bip32Path string,
		signature *types.ByteData,
	) (isVerify bool, err error)
}

// NewPeginService This function returns an object that defines the API for Pegin.
func NewPeginService() *PeginService {
	return &PeginService{}
}

// -------------------------------------
// PeginService
// -------------------------------------

// PeginService This struct is implements pegin api.
type PeginService struct {
	Network *types.NetworkType
}

// GetPubkeyFromExtPubkey This function get the pubkey from xpubkey.
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
	// FIXME implements extPubkey validation
	// FIXME implements bip32Path validation
	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, p.Network.ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, err
	}
	pubkeyHex, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.Network.ToCfdValue())
	if err != nil {
		return nil, nil, err
	}
	// FIXME implements depth check
	return &types.Pubkey{Hex: pubkeyHex}, &types.ExtPubkey{Key: deriveKey}, nil
}

// CreatePeginAddress This function get the pegin address and claim script.
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
	switch addressType {
	case types.P2shAddress:
	case types.P2wshAddress:
	case types.P2shP2wshAddress:
		break
	default:
		return nil, nil, nil, fmt.Errorf("CFD Error: Invalid pegin address type")
	}
	// FIXME implements extPubkey validation
	// FIXME implements bip32Path validation
	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, p.Network.ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, nil, err
	}
	// FIXME implements depth check
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

// CreatePeginTransaction This function create the pegin claim transaction.
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

// VerifyPubkeySignature This function validate the signature by pubkey.
func (p *PeginService) VerifyPubkeySignature(
	proposalTx *types.Transaction,
	utxoList *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	// FIXME implements
	// 1. pegin: auto-get amount etc.
	// 2. other utxo: normal verify
	return false, nil
}

// VerifyPubkeySignature This function validate the pegin signature by pubkey.
func (p *PeginService) VerifyPeginPubkeySignature(
	proposalTx *types.Transaction,
	extPubkey *types.ExtPubkey,
	bip32Path string,
	signature *types.ByteData,
) (isVerify bool, err error) {
	// FIXME implements
	// 1. pegin: auto-get amount etc.
	return false, nil
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
