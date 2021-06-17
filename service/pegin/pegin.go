package pegin

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// wrap and validation APIs
type PeginApi interface {
	// CreatePeginAddress ...
	CreatePeginAddress(
		addressType types.AddressType,
		extPubkey *types.ExtPubkey,
		bip32Path string,
		fedpegScript *types.Script,
	) (
		peginAddress *types.Address,
		claimScript *types.Script,
		err error,
	)
	// CreatePeginTransaction ...
	CreatePeginTransaction(
		peginOutPoint *types.OutPoint,
		peginData *types.InputPeginData,
		utxoList *[]types.ElementsUtxoData,
		sendList []types.InputConfidentialTxOut,
		changeData *types.InputConfidentialTxOut,
		option *types.FundRawTxOption,
	) (tx *types.ConfidentialTx, err error)
}

func NewPeginApi() PeginApi {
	return &PeginUtil{}
}

// -------------------------------------
// PeginUtil
// -------------------------------------

type PeginUtil struct {
	Network *types.NetworkType
}

func (p *PeginUtil) validConfig() error {
	if p.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		if cfdConfig.Network.IsElements() {
			netType := cfdConfig.Network.ToBitcoinType()
			p.Network = &netType
		} else {
			netType := cfdConfig.Network
			p.Network = &netType
		}
	}
	if !p.Network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

func (p *PeginUtil) CreatePeginAddress(
	addressType types.AddressType,
	extPubkey *types.ExtPubkey,
	bip32Path string,
	fedpegScript *types.Script,
) (
	peginAddress *types.Address,
	claimScript *types.Script,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, err
	}
	addrApi := address.NewAddressApi()
	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, p.Network.ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, err
	}
	pubkey, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.Network.ToCfdValue())
	if err != nil {
		return nil, nil, err
	}
	return addrApi.GetPeginAddressByPubkey(addressType, fedpegScript.ToHex(), pubkey)
}

func (p *PeginUtil) CreatePeginTransaction(
	peginOutPoint *types.OutPoint,
	peginData *types.InputPeginData,
	utxoList *[]types.ElementsUtxoData,
	sendList []types.InputConfidentialTxOut,
	changeData *types.InputConfidentialTxOut,
	option *types.FundRawTxOption,
) (tx *types.ConfidentialTx, err error) {
	// FIXME implements
	// 1. create transaction
	// 2. add txout by output if single output.
	// 3. fundrawtransaction
	// 4. blind
	return nil, nil
}
