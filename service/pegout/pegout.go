package pegout

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// Pegout This interface defines the API used by the pegout function.
type Pegout interface {
	// CreateOnlinePrivateKey This function generate random private key for online key.
	CreateOnlinePrivateKey() (privkey *types.Privkey, err error)
	// CreatePakEntry This function create the PAK-Entry.
	CreatePakEntry(
		extPubkey *types.ExtPubkey,
		onlinePrivkey *types.Privkey,
	) (pakEntry *types.ByteData, err error)
	// CreatePegoutAddress This function create the pegout address for bitcoin network.
	CreatePegoutAddress(
		addressType types.AddressType,
		extPubkey *types.ExtPubkey,
		accountIndex uint32,
	) (
		pegoutAddress *types.Address,
		err error,
	)
	// CreatePegoutTransaction This function create the pegout transaction.
	CreatePegoutTransaction(
		utxoList []types.ElementsUtxoData,
		pegoutData types.InputConfidentialTxOut,
		sendList *[]types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.FundRawTxOption,
	) (tx *types.ConfidentialTx, err error)
	// VerifyPubkeySignature This function validate the signature by pubkey.
	VerifyPubkeySignature(
		proposalTx *types.Transaction,
		utxoList *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
}

// NewPegoutService This function returns an object that defines the API for Pegout.
func NewPegoutService() *PegoutService {
	return &PegoutService{}
}

// -------------------------------------
// PegoutService
// -------------------------------------

// PegoutService This struct is implements pegout api.
type PegoutService struct {
	Network *types.NetworkType
}

// CreateOnlinePrivateKey This function generate random private key for online key.
func (p *PegoutService) CreateOnlinePrivateKey() (privkey *types.Privkey, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	_, privkeyHex, wif, err := cfd.CfdGoCreateKeyPair(true, p.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Privkey{
		Hex:                privkeyHex,
		Wif:                wif,
		Network:            *p.Network,
		IsCompressedPubkey: true,
	}, nil
}

// CreatePakEntry This function create the PAK-Entry.
func (p *PegoutService) CreatePakEntry(
	extPubkey *types.ExtPubkey,
	onlinePrivkey *types.Privkey,
) (pakEntry *types.ByteData, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	if err = validateExtPubkey(extPubkey); err != nil {
		return nil, err
	}
	// FIXME implements privkey validation

	offlinePubkey, err := cfd.CfdGoGetPubkeyFromExtkey(extPubkey.Key, p.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, err
	}
	offlineNegatePubkey, err := cfd.CfdGoNegatePubkey(offlinePubkey)
	if err != nil {
		return nil, err
	}
	// FIXME implements privkey wif pattern
	onlinePubkey, err := cfd.CfdGoGetPubkeyFromPrivkey(onlinePrivkey.Hex, "", true)
	if err != nil {
		return nil, err
	}
	pakEntryObj, err := types.NewByteDataFromHex(offlineNegatePubkey + onlinePubkey)
	if err != nil {
		return nil, err
	}
	return &pakEntryObj, nil
}

// CreatePegoutAddress This function create the pegout address for bitcoin network.
func (p *PegoutService) CreatePegoutAddress(
	addressType types.AddressType,
	extPubkey *types.ExtPubkey,
	accountIndex uint32,
) (pegoutAddress *types.Address, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	switch addressType {
	case types.P2pkhAddress:
	case types.P2wpkhAddress:
	case types.P2shP2wpkhAddress:
		break
	default:
		return nil, fmt.Errorf("CFD Error: Invalid pegout address type")
	}
	if err = validateExtPubkey(extPubkey); err != nil {
		return nil, err
	}
	if accountIndex >= 0x80000000 {
		return nil, fmt.Errorf("CFD Error: Invalid account index. The hardened index can not used on the pegout")
	}

	address, _, err := cfd.CfdGoGetPegoutAddress(p.Network.ToBitcoinType().ToCfdValue(), p.Network.ToCfdValue(), extPubkey.Key, accountIndex, addressType.ToCfdValue())
	if err != nil {
		return nil, err
	}
	return &types.Address{
		Address: address,
		Network: p.Network.ToBitcoinType(),
		Type:    addressType,
	}, nil
}

// CreatePegoutTransaction This function create the pegout transaction.
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

// VerifyPubkeySignature This function validate the signature by pubkey.
func (p *PegoutService) VerifyPubkeySignature(
	proposalTx *types.Transaction,
	utxoList *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	// FIXME implements
	return false, nil
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

func validateExtPubkey(extPubkey *types.ExtPubkey) error {
	if extPubkey == nil {
		return fmt.Errorf("CFD Error: Pegout extkey is null")
	}
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return err
	}
	if data.Depth != 3 {
		return fmt.Errorf("CFD Error: Invalid pegout extkey depth")
	}
	return nil
}
