package pegin

import (
	"fmt"

	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// wrap and validation APIs
type Pegout interface {
	// CreateOnliePrivateKey ...
	CreateOnliePrivateKey() (privkey *types.Privkey, err error)
	// CreatePakEntry
	CreatePakEntry(
		extPubkey *types.ExtPubkey,
		onlinePrivkey *types.Privkey,
	) (pakEntry *types.ByteData, err error)
	// CreatePeginAddress ...
	CreatePegoutAddress(
		addressType types.AddressType,
		extPubkey *types.ExtPubkey,
		accountIndex uint32,
	) (
		pegoutAddress *types.Address,
		err error,
	)
	// CreatePegoutTransaction ...
	CreatePegoutTransaction(
		utxoList []types.ElementsUtxoData,
		pegoutData types.InputConfidentialTxOut,
		sendList *[]types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.FundRawTxOption,
	) (tx *types.ConfidentialTx, err error)
	// VerifyPubkeySignature
	VerifyPubkeySignature(
		proposalTx *types.Transaction,
		utxoList *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
}

func NewPegoutService() *PegoutService {
	return &PegoutService{}
}

// -------------------------------------
// PeginUtil
// -------------------------------------

type PegoutService struct {
	Network *types.NetworkType
}

func (p *PegoutService) validConfig() error {
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

func (p *PegoutService) CreateOnliePrivateKey() (privkey *types.Privkey, err error) {
	return nil, nil
}

func (p *PegoutService) CreatePakEntry(
	extPubkey *types.ExtPubkey,
	onlinePrivkey *types.Privkey,
) (pakEntry *types.ByteData, err error) {
	return nil, err
}

func (p *PegoutService) CreatePegoutAddress(
	addressType types.AddressType,
	extPubkey *types.ExtPubkey,
	accountIndex uint32,
) (
	pegoutAddress *types.Address,
	err error,
) {
	return nil, err
}

func (p *PegoutService) CreatePegoutTransaction(
	utxoList []types.ElementsUtxoData,
	pegoutData types.InputConfidentialTxOut,
	sendList *[]types.InputConfidentialTxOut,
	changeAddress *string,
	option *types.FundRawTxOption,
) (tx *types.ConfidentialTx, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	// FIXME implements
	// 1. create transaction
	// 2. add txout by output if single output.
	// 3. fundrawtransaction
	// 4. blind
	return nil, nil
}

func (p *PegoutService) VerifyPubkeySignature(
	proposalTx *types.Transaction,
	utxoList *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	return false, nil
}
