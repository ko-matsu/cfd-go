package pegin

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"

	"github.com/pkg/errors"
)

// Pegin This interface defines the API used by the pegin function.
type Pegin interface {
	// GetPubkeyFromAccountExtPubkey This function get the pubkey from xpubkey.
	GetPubkeyFromAccountExtPubkey(
		accountExtPubkey *types.ExtPubkey,
		bip32Path string, // change and index path
	) (
		pubkey *types.Pubkey,
		derivedExtPubkey *types.ExtPubkey,
		err error,
	)
	// CreatePeginAddress This function get the pegin address and claim script.
	CreatePeginAddress(
		addressType types.AddressType,
		pubkey *types.Pubkey,
		fedpegScript *types.Script,
	) (peginAddress *types.Address, claimScript *types.Script, err error)
	// CreatePeginTransaction This function create the pegin claim transaction.
	CreatePeginTransaction(
		peginOutPoint *types.OutPoint,
		peginData *types.InputPeginData,
		utxoList *[]types.ElementsUtxoData,
		sendList []types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.PeginTxOption,
	) (tx *types.ConfidentialTx, err error)
	// VerifyPubkeySignature This function validate the signature by pubkey.
	VerifyPubkeySignature(
		proposalTx *types.ConfidentialTx,
		utxoData *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
	// GetPeginUtxoData This function get the pegin utxo data from transaction.
	GetPeginUtxoData(
		proposalTx *types.ConfidentialTx,
		peginOutPoint *types.OutPoint,
		pubkey *types.Pubkey,
	) (utxoData *types.ElementsUtxoData, err error)
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
func (p *PeginService) GetPubkeyFromAccountExtPubkey(
	accountExtPubkey *types.ExtPubkey,
	bip32Path string,
) (
	pubkey *types.Pubkey,
	derivedExtPubkey *types.ExtPubkey,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin invalid configuration")
	}
	if err = validatePeginExtPubkey(accountExtPubkey); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin extPubkey validation error")
	}

	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(accountExtPubkey.Key, bip32Path, p.Network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin extPubkey derive error")
	}
	derivedExtPubkey = &types.ExtPubkey{Key: deriveKey}
	if err = validateDerivedExtPubkey(derivedExtPubkey); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin derive extPubkey validation error")
	}

	pubkeyHex, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin pubkey get error")
	}
	return &types.Pubkey{Hex: pubkeyHex}, derivedExtPubkey, nil
}

// CreatePeginAddress This function get the pegin address and claim script.
func (p *PeginService) CreatePeginAddress(
	addressType types.AddressType,
	pubkey *types.Pubkey,
	fedpegScript *types.Script,
) (
	peginAddress *types.Address,
	claimScript *types.Script,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, err
	}

	switch addressType {
	case types.P2shAddress:
	case types.P2wshAddress:
	case types.P2shP2wshAddress:
		break
	default:
		return nil, nil, fmt.Errorf("CFD Error: Invalid pegin address type")
	}

	addrApi := address.AddressApiImpl{Network: p.Network.ToBitcoinTypePointer()}
	peginAddress, claimScript, err = addrApi.GetPeginAddressByPubkey(addressType, fedpegScript.ToHex(), pubkey.Hex)
	if err != nil {
		return nil, nil, err
	}
	return peginAddress, claimScript, nil
}

// CreatePeginTransaction This function create the pegin claim transaction.
func (p *PeginService) CreatePeginTransaction(
	peginOutPoint *types.OutPoint,
	peginData *types.InputPeginData,
	utxoList *[]types.ElementsUtxoData,
	sendList []types.InputConfidentialTxOut,
	changeAddress *string,
	option *types.PeginTxOption,
) (tx *types.ConfidentialTx, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	assetId := ""
	cfdConfig := config.GetCurrentCfdConfig()
	if len(cfdConfig.BitcoinAssetId) == 64 {
		assetId = cfdConfig.BitcoinAssetId
	} else {
		assetId = peginData.BitcoinAssetId
	}

	txApi := transaction.ConfidentialTxApiImpl{Network: p.Network}
	caApi := address.ConfidentialAddressApiImpl{}

	// FIXME validation utxoList
	// FIXME validation peginData

	var changeAddr *types.ConfidentialAddress
	if changeAddress != nil {
		changeAddr, err = caApi.Parse(*changeAddress)
		if err != nil {
			return nil, errors.Wrap(err, "Pegin changeAddress error")
		} else if changeAddr.Network != *p.Network {
			return nil, errors.Wrap(err, "Pegin changeAddress network check error")
		}
	}

	// validation sendList
	blindOutputCount, hasAppendDummyOutput, amount, err := validateTxOutList(&sendList, p.Network, changeAddr)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin sendList validation error")
	}
	if option.IsBlindTx && (blindOutputCount == 0) {
		return nil, errors.Wrap(err, "Pegin sendList empty blinding output error")
	} else if !option.IsBlindTx && (blindOutputCount > 0) {
		return nil, errors.Wrap(err, "Pegin sendList exist blinding output error")
	}

	txins := []types.InputConfidentialTxIn{
		{
			OutPoint:   *peginOutPoint,
			PeginInput: peginData,
		},
	}
	tx, err = txApi.Create(uint32(2), uint32(0), &txins, &sendList, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin CT.Create error")
	}

	// 2. add txout by output if single output.
	if hasAppendDummyOutput {
		tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.Network)
		if err != nil {
			return nil, errors.Wrap(err, "Pegin append dummy output error")
		}
	}

	// 3. fundrawtransaction
	peginAmount, _, err := cfd.CfdGoGetTxOut(p.Network.ToBitcoinType().ToCfdValue(), peginData.BitcoinTransaction, peginOutPoint.Vout)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin get btc txout error")
	}
	fundTxInList := make([]cfd.CfdUtxo, 1)
	fundTxInList[0].Txid = peginOutPoint.Txid
	fundTxInList[0].Vout = peginOutPoint.Vout
	fundTxInList[0].Amount = peginAmount
	fundTxInList[0].Asset = assetId
	fundTxInList[0].IsPegin = true
	fundTxInList[0].PeginBtcTxSize = uint32(len(peginData.BitcoinTransaction) / 2)
	fundTxInList[0].FedpegScript = peginData.ClaimScript
	fundTxInList[0].Descriptor = "wpkh(02" + assetId + ")" // dummy

	utxoListLen := 0
	if utxoList != nil {
		utxoListLen = len(*utxoList)
	}
	fundUtxoList := make([]cfd.CfdUtxo, utxoListLen)
	utxoMap := make(map[types.OutPoint]*types.ElementsUtxoData, utxoListLen)
	if utxoList != nil {
		for i, txin := range *utxoList {
			fundUtxoList[i].Txid = txin.OutPoint.Txid
			fundUtxoList[i].Vout = txin.OutPoint.Vout
			fundUtxoList[i].Amount = txin.Amount
			fundUtxoList[i].Asset = txin.Asset
			fundUtxoList[i].Descriptor = txin.Descriptor
			fundUtxoList[i].AmountCommitment = txin.AmountCommitment
			utxoMap[txin.OutPoint] = &txin
		}
	}
	targetAmounts := []cfd.CfdFundRawTxTargetAmount{
		{
			Amount: 0,
			Asset:  assetId,
		},
	}
	if amount == 0 {
		targetAmounts[0].Amount = 1
	}
	if changeAddress != nil {
		targetAmounts[0].ReservedAddress = *changeAddress
	}
	fundOption := cfd.NewCfdFundRawTxOption(p.Network.ToCfdValue())
	fundOption.FeeAsset = assetId
	fundOption.EffectiveFeeRate = option.EffectiveFeeRate
	fundOption.LongTermFeeRate = option.LongTermFeeRate
	fundOption.DustFeeRate = option.DustFeeRate
	fundOption.IsBlindTx = option.IsBlindTx
	fundOption.KnapsackMinChange = option.KnapsackMinChange
	fundOption.Exponent = option.Exponent
	fundOption.MinimumBits = option.MinimumBits
	outputTx, _, _, err := cfd.CfdGoFundRawTransaction(p.Network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
	if err != nil {
		return nil, errors.Wrapf(err, "Pegin FundRawTransaction error (tx: %s)", tx.Hex)
	}
	outputCount, err := cfd.CfdGoGetTxOutCount(p.Network.ToCfdValue(), outputTx)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin GetTxOutCount error")
	}

	// 4. check to need append dummy output
	if !hasAppendDummyOutput && (outputCount == 2) { // 2 = output + fee
		tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.Network)
		if err != nil {
			return nil, errors.Wrap(err, "Pegin append dummy output error")
		}
		outputTx, _, _, err = cfd.CfdGoFundRawTransaction(p.Network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
		if err != nil {
			return nil, errors.Wrap(err, "Pegin FundRawTransaction error")
		}
	}
	tx.Hex = outputTx

	_, inputs, _, err := txApi.GetAll(tx, false)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin GetTxAll error")
	}

	// 5. blind
	blindInputList := make([]types.BlindInputData, len(inputs))
	for i, txin := range inputs {
		blindInputList[i].OutPoint = txin.OutPoint
		if txin.OutPoint.Equal(*peginOutPoint) {
			blindInputList[i].Amount = peginAmount
			blindInputList[i].Asset = assetId
		} else {
			utxo, ok := utxoMap[txin.OutPoint]
			if !ok {
				return nil, fmt.Errorf("CFD Error: Internal error")
			}
			blindInputList[i].Amount = utxo.Amount
			blindInputList[i].Asset = utxo.Asset
			blindInputList[i].ValueBlindFactor = utxo.ValueBlindFactor
			blindInputList[i].AssetBlindFactor = utxo.AssetBlindFactor
		}
	}
	blindOption := types.NewBlindTxOption()
	blindOption.MinimumRangeValue = option.MinimumRangeValue
	blindOption.Exponent = option.Exponent
	blindOption.MinimumBits = option.MinimumBits
	err = txApi.Blind(tx, blindInputList, nil, &blindOption)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin Blind error")
	}
	return tx, nil
}

// VerifyPubkeySignature This function validate the signature by pubkey.
func (p *PeginService) VerifyPubkeySignature(
	proposalTx *types.ConfidentialTx,
	utxoData *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	if err = p.validConfig(); err != nil {
		return false, err
	}
	// FIXME implements
	txApi := transaction.ConfidentialTxApiImpl{Network: p.Network}
	descApi := descriptor.DescriptorApiImpl{Network: p.Network}
	pubkeyApi := key.NewPubkeyApi()

	sig, cfdSighashType, _, err := cfd.CfdGoDecodeSignatureFromDer(signature.ToHex())
	if err != nil {
		return false, errors.Wrap(err, "Pegin decode signature error")
	}
	sighashType := types.NewSigHashType(cfdSighashType)
	utxoList := []types.UtxoData{
		{
			Txid:             utxoData.OutPoint.Txid,
			Vout:             utxoData.OutPoint.Vout,
			Amount:           utxoData.Amount,
			AmountCommitment: utxoData.AmountCommitment,
			Descriptor:       utxoData.Descriptor,
			Asset:            utxoData.Asset,
		},
	}
	sighash, err := txApi.GetSighash(proposalTx, &utxoData.OutPoint, *sighashType, &utxoList)
	if err != nil {
		return false, errors.Wrap(err, "Pegin decode signature error")
	}
	desc := types.Descriptor{OutputDescriptor: utxoData.Descriptor}
	descData, _, _, err := descApi.Parse(&desc)
	if err != nil {
		return false, errors.Wrap(err, "Pegin parse descriptor error")
	} else if descData.KeyType == int(cfd.KCfdDescriptorKeyNull) {
		return false, errors.Wrap(err, "Pegin descriptor unsupport key type")
	}
	pubkey := types.Pubkey{Hex: descData.Pubkey}
	return pubkeyApi.VerifyEcSignature(&pubkey, sighash.ToHex(), sig)
}

// GetPeginUtxoData This function get the pegin utxo data from transaction.
func (p *PeginService) GetPeginUtxoData(
	proposalTx *types.ConfidentialTx,
	peginOutPoint *types.OutPoint,
	pubkey *types.Pubkey,
) (utxoData *types.ElementsUtxoData, err error) {
	if err = p.validConfig(); err != nil {
		return nil, err
	}
	txApi := transaction.ConfidentialTxApiImpl{Network: p.Network}
	btcTxApi := transaction.TransactionApiImpl{Network: p.Network.ToBitcoinTypePointer()}
	input, err := txApi.GetTxIn(proposalTx.Hex, peginOutPoint)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin get txin index error")
	} else if len(input.PeginWitness.Stack) == 0 {
		return nil, errors.Wrap(err, "Target outpoint is not pegin")
	}
	btcTx := types.Transaction{Hex: input.PeginWitness.Stack[4]}
	output, err := btcTxApi.GetTxOut(&btcTx, peginOutPoint.Vout)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin get btc tx error")
	}

	utxoData = &types.ElementsUtxoData{
		OutPoint:   *peginOutPoint,
		Amount:     output.Amount,
		Descriptor: "wpkh(" + pubkey.Hex + ")",
		Asset:      input.PeginWitness.Stack[1],
	}
	return utxoData, nil
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

func validatePeginExtPubkey(extPubkey *types.ExtPubkey) error {
	if extPubkey == nil {
		return fmt.Errorf("CFD Error: Pegin extkey is null")
	}
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return err
	}
	if data.Depth != 3 {
		return fmt.Errorf("CFD Error: Invalid pegin extkey depth (%d)", data.Depth)
	}
	return nil
}

func validateDerivedExtPubkey(extPubkey *types.ExtPubkey) error {
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return err
	}
	if data.Depth != 5 {
		return fmt.Errorf("CFD Error: Invalid pegin derive depth (%d)", data.Depth)
	}
	return nil
}

func validateTxOutList(sendList *[]types.InputConfidentialTxOut, network *types.NetworkType, changeAddress *types.ConfidentialAddress) (blindOutputCount uint32, hasAppendDummyOutput bool, amount int64, err error) {
	caApi := address.ConfidentialAddressApiImpl{}
	blindOutputCount = uint32(0)
	unblindOutputCount := uint32(0)
	feeCount := uint32(0)
	for index, txout := range *sendList {
		isFee := false
		if txout.PegoutInput != nil {
			return 0, false, 0, errors.Wrapf(err, "Pegin sendList exist pegout data error(n: %d)", index)
		} else if txout.IsFee {
			isFee = true
		} else if len(txout.Nonce) == types.CommitmentHexDataSize {
			if txout.IsDestroy || len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
				blindOutputCount += 1
				if txout.IsDestroy && (len(txout.LockingScript) > 0 || len(txout.Address) > 0) {
					return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid destroy amount error(n: %d)", index)
				}
			} else {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid nonce error(n: %d)", index)
			}
		} else if txout.IsDestroy {
			if len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid destroy amount error(n: %d)", index)
			}
			unblindOutputCount += 1
		} else if len(txout.Address) > 0 {
			addrInfo, err := caApi.Parse(txout.Address)
			if err != nil {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList address check error(n: %d)", index)
			} else if addrInfo.Network != *network {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList address network check error(n: %d)", index)
			} else if len(addrInfo.ConfidentialAddress) > 0 {
				blindOutputCount += 1
			} else {
				unblindOutputCount += 1
			}
		} else if len(txout.LockingScript) > 0 {
			unblindOutputCount += 1
		} else {
			isFee = true
		}

		if isFee {
			feeCount += 1
		} else {
			amount += txout.Amount
		}
	}

	if changeAddress == nil {
		if blindOutputCount == 1 {
			hasAppendDummyOutput = true
		}
	} else if len(changeAddress.ConfidentialAddress) == 0 {
		if blindOutputCount > 0 {
			return 0, false, 0, errors.Wrap(err, "Pegin sendList mixed output error (changeAddress is blinded)")
		}
		unblindOutputCount += 1
	} else {
		blindOutputCount += 1
	}

	if feeCount > 1 {
		return 0, false, 0, errors.Wrapf(err, "Pegin sendList fee output check error(count: %d)", feeCount)
	} else if (blindOutputCount == 0) && (unblindOutputCount == 0) {
		return 0, false, 0, errors.Wrap(err, "Pegin sendList output empty error")
	} else if (blindOutputCount > 0) && (unblindOutputCount > 0) {
		return 0, false, 0, errors.Wrap(err, "Pegin sendList mixed output error (blind & unblind)")
	}
	return blindOutputCount, hasAppendDummyOutput, amount, nil
}

func appendDummyOutput(txHex string, assetId string, network *types.NetworkType) (outputTxHex string, err error) {
	// generate random confidential key
	nonce, _, _, err := cfd.CfdGoCreateKeyPair(true, network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return "", err
	}
	outputTxHex, err = cfd.CfdGoAddConfidentialTxOut(txHex, assetId, 0, "", "", "6a", nonce)
	if err != nil {
		return "", err
	}
	return outputTxHex, nil
}
