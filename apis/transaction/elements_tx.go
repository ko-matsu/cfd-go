package transaction

import (
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

const (
	EmptyBlinder string = types.EmptyBlinder
)

// ConfidentialTxApi This interface defines the API to operate Elements Confidential Transaction.
type ConfidentialTxApi interface {
	// Create This function create the elements transaction.
	Create(version uint32, locktime uint32, txinList *[]types.InputConfidentialTxIn, txoutList *[]types.InputConfidentialTxOut, pegoutAddressList *[]string) (tx *types.ConfidentialTx, err error)
	// Add This function add the inputs and outputs.
	Add(tx *types.ConfidentialTx, txinList *[]types.InputConfidentialTxIn, txoutList *[]types.InputConfidentialTxOut, pegoutAddressList *[]string) error
	// Blind This function change to the blinded transaction.
	Blind(tx *types.ConfidentialTx, txinList []types.BlindInputData, txoutList *[]types.BlindOutputData, option *types.BlindTxOption) error
	// AddPubkeySign This function add the pubkey hash sign.
	AddPubkeySign(tx *types.ConfidentialTx, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error
	// AddPubkeySign This function add the pubkey hash sign by output descriptor.
	AddPubkeySignByDescriptor(tx *types.ConfidentialTx, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error
	VerifySign(tx *types.ConfidentialTx, outpoint *types.OutPoint, txinUtxoList *[]types.ElementsUtxoData) (isVerify bool, reason string, err error)
	FilterUtxoByTxInList(tx *types.ConfidentialTx, utxoList *[]types.ElementsUtxoData) (txinUtxoList []types.ElementsUtxoData, err error)
	GetTxid(tx *types.ConfidentialTx) string
	GetPegoutAddress(tx *types.ConfidentialTx, index uint32) (pegoutAddress *types.Address, isPegoutOutput bool, err error)
	GetSighash(tx *types.ConfidentialTx, outpoint *types.OutPoint, sighashType types.SigHashType, utxoList *[]types.ElementsUtxoData) (sighash *types.ByteData, err error)
	GetAll(tx *types.ConfidentialTx, hasWitness bool) (data *types.TransactionData, txinList []types.ConfidentialTxIn, txoutList []types.ConfidentialTxOut, err error)
	GetTxIn(txHex string, outpoint *types.OutPoint) (txin *types.ConfidentialTxIn, err error)
}

// NewConfidentialTxApi This function returns a struct that implements ConfidentialTxApi.
func NewConfidentialTxApi(options ...config.CfdConfigOption) *ConfidentialTxApiImpl {
	api := ConfidentialTxApiImpl{}
	var err error
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		api.setError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsElements() {
		api.setError(cfdErrors.ElementsNetworkError)
	} else {
		network = conf.Network
	}

	var bitcoinAssetId *types.ByteData
	if len(conf.BitcoinAssetId) != 0 {
		if bitcoinAssetId, err = utils.ValidAssetId(conf.BitcoinAssetId); err != nil {
			api.setError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}
	var bitcoinGenesisBlockHash *types.ByteData
	if len(conf.BitcoinGenesisBlockHash) != 0 {
		if bitcoinGenesisBlockHash, err = utils.ValidBlockHash(conf.BitcoinGenesisBlockHash); err != nil {
			api.setError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}

	if network.Valid() {
		api.network = &network
		api.bitcoinAssetId = bitcoinAssetId
		api.bitcoinGenesisBlockHash = bitcoinGenesisBlockHash

		elementsConfOpts := api.getConfig().GetOptions()
		descriptorApi := descriptor.NewDescriptorApi(elementsConfOpts...)
		if descriptorApi.InitializeError != nil {
			api.setError(descriptorApi.InitializeError)
		} else {
			api.descriptorApi = descriptorApi
		}

		btcNetworkOpt := config.NetworkOpt(network.ToBitcoinType())
		bitcoinAddressApi := address.NewAddressApi(btcNetworkOpt)
		if bitcoinAddressApi.InitializeError != nil {
			api.setError(bitcoinAddressApi.InitializeError)
		} else {
			api.bitcoinAddressApi = bitcoinAddressApi
		}
		bitcoinTxApi := NewTransactionApi(btcNetworkOpt)
		if bitcoinTxApi.InitializeError != nil {
			api.setError(bitcoinTxApi.InitializeError)
		} else {
			api.bitcoinTxApi = bitcoinTxApi
		}
	}
	return &api
}

// -------------------------------------
// ConfidentialTxApiImpl
// -------------------------------------

// ConfidentialTxApiImpl Create confidential transaction utility.
type ConfidentialTxApiImpl struct {
	InitializeError         error
	network                 *types.NetworkType
	bitcoinGenesisBlockHash *types.ByteData
	bitcoinAssetId          *types.ByteData
	descriptorApi           descriptor.DescriptorApi
	bitcoinAddressApi       address.AddressApi
	bitcoinTxApi            TransactionApi
}

// WithElementsDescriptorApi This function set a elements descriptor api.
func (p *ConfidentialTxApiImpl) WithElementsDescriptorApi(descriptorApi descriptor.DescriptorApi) *ConfidentialTxApiImpl {
	if descriptorApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else if !utils.ValidNetworkTypes(descriptorApi.GetNetworkTypes(), types.LiquidV1) {
		p.setError(cfdErrors.ElementsNetworkError)
	} else {
		p.descriptorApi = descriptorApi
	}
	return p
}

// WithBitcoinAddressApi This function set a bitcoin address api.
func (p *ConfidentialTxApiImpl) WithBitcoinAddressApi(addressApi address.AddressApi) *ConfidentialTxApiImpl {
	if addressApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else if !utils.ValidNetworkTypes(addressApi.GetNetworkTypes(), types.Mainnet) {
		p.setError(cfdErrors.BitcoinNetworkError)
	} else {
		p.bitcoinAddressApi = addressApi
	}
	return p
}

// WithBitcoinTxApi This function set a bitcoin transaction api.
func (p *ConfidentialTxApiImpl) WithBitcoinTxApi(transactionApi TransactionApi) *ConfidentialTxApiImpl {
	if transactionApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else {
		p.bitcoinTxApi = transactionApi
	}
	return p
}

func (p *ConfidentialTxApiImpl) setError(err error) {
	if err == nil {
		return
	}
	multiError, ok := p.InitializeError.(*cfdErrors.MultiError)
	if !ok {
		multiError = cfdErrors.NewMultiError(
			cfdErrors.CfdError("CFD Error: ConfidentialTxApiImpl initialize error"))
	}
	multiError.Add(err)
	p.InitializeError = multiError
}

func (t *ConfidentialTxApiImpl) Create(version uint32, locktime uint32, txinList *[]types.InputConfidentialTxIn, txoutList *[]types.InputConfidentialTxOut, pegoutAddressList *[]string) (tx *types.ConfidentialTx, err error) {
	if err = t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	txHandle, err := cfd.InitializeTransaction(t.network.ToCfdValue(), version, locktime)
	if err != nil {
		return nil, errors.Wrap(err, "initialize tx error")
	}
	defer cfd.FreeTransactionHandle(txHandle)

	if err = t.addConidentialTx(txHandle, *t.network, locktime, txinList, txoutList, pegoutAddressList); err != nil {
		return nil, errors.Wrap(err, "add tx error")
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return nil, errors.Wrap(err, "finalize tx error")
	}
	if txoutList != nil {
		txHex, err = updateDirectNonce(txHandle, txHex, txoutList)
		if err != nil {
			return nil, errors.Wrap(err, "update nonce error")
		}
	}
	tx = &types.ConfidentialTx{Hex: txHex}
	return tx, nil

}

func (t *ConfidentialTxApiImpl) validConfig() error {
	if t.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !t.network.IsElements() {
		return cfdErrors.ElementsNetworkError
	}
	return nil
}

func (p *ConfidentialTxApiImpl) getConfig() *config.CfdConfig {
	conf := config.CfdConfig{Network: *p.network}
	if p.bitcoinAssetId != nil {
		conf.BitcoinAssetId = p.bitcoinAssetId.ToHex()
	}
	if p.bitcoinGenesisBlockHash != nil {
		conf.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	return &conf
}

func (t *ConfidentialTxApiImpl) Add(tx *types.ConfidentialTx, txinList *[]types.InputConfidentialTxIn, txoutList *[]types.InputConfidentialTxOut, pegoutAddressList *[]string) error {
	if err := t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	txHandle, err := cfd.InitializeTransactionByHex(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return errors.Wrap(err, "initialize tx error")
	}
	defer cfd.FreeTransactionHandle(txHandle)

	data, err := cfd.CfdGoGetConfidentialTxDataByHandle(txHandle)
	if err != nil {
		return errors.Wrap(err, "get tx data error")
	}

	if err = t.addConidentialTx(txHandle, *t.network, data.LockTime, txinList, txoutList, pegoutAddressList); err != nil {
		return errors.Wrap(err, "add tx error")
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return errors.Wrap(err, "finalize tx error")
	}
	if txoutList != nil {
		txHex, err = updateDirectNonce(txHandle, txHex, txoutList)
		if err != nil {
			return errors.Wrap(err, "update nonce error")
		}
	}
	tx.Hex = txHex
	return nil
}

//func (t *ConfidentialTx) SetReissueAsset() error {
// FIXME need implements
//}

// Blind ...
func (t *ConfidentialTxApiImpl) Blind(tx *types.ConfidentialTx, txinList []types.BlindInputData, txoutList *[]types.BlindOutputData, option *types.BlindTxOption) error {
	var err error
	if err = t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	lbtcAsset, _ := t.getDefaultBitcoinData()

	txHex := tx.Hex
	if option != nil && option.AppendDummyOutput {
		txHex, err = appendDummyOutput(txHex, *t.network, &txinList)
		if err != nil {
			return errors.Wrap(err, "add dummy txout error")
		}
	}
	// convert list
	blindTxinList := make([]cfd.CfdBlindInputData, len(txinList))
	for index, input := range txinList {
		blindTxinList[index].Txid = input.OutPoint.Txid
		blindTxinList[index].Vout = input.OutPoint.Vout
		blindTxinList[index].Amount = input.Amount
		blindTxinList[index].ValueBlindFactor = input.ValueBlindFactor
		blindTxinList[index].Asset = input.Asset
		blindTxinList[index].AssetBlindFactor = input.AssetBlindFactor
		if input.IssuanceKey != nil {
			blindTxinList[index].AssetBlindingKey = input.IssuanceKey.AssetBlindingKey
			blindTxinList[index].TokenBlindingKey = input.IssuanceKey.TokenBlindingKey
		}
		if len(blindTxinList[index].Asset) == 0 {
			blindTxinList[index].Asset = lbtcAsset
		}
	}
	var blindOutputList []cfd.CfdBlindOutputData
	if txoutList != nil {
		blindOutputList = make([]cfd.CfdBlindOutputData, len(*txoutList))
		for i, data := range *txoutList {
			blindOutputList[i] = cfd.CfdBlindOutputData{
				Index:               data.Index,
				ConfidentialAddress: data.ConfidentialAddress,
				ConfidentialKey:     data.ConfidentialKey,
			}
		}
	}
	blindOption := &cfd.CfdBlindTxOption{
		MinimumRangeValue: option.MinimumRangeValue,
		Exponent:          option.Exponent,
		MinimumBits:       option.MinimumBits,
	}
	outputTx, err := cfd.CfdGoBlindRawTransaction(txHex, blindTxinList, blindOutputList, blindOption)
	if err != nil {
		return errors.Wrap(err, "blind tx error")
	}
	tx.Hex = outputTx
	return nil
}

// AddPubkeySign ...
func (t *ConfidentialTxApiImpl) AddPubkeySign(tx *types.ConfidentialTx, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error {
	if err := t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	signParam := cfd.CfdSignParameter{
		Data:                signature,
		IsDerEncode:         false,
		SighashType:         int(cfd.KCfdSigHashAll),
		SighashAnyoneCanPay: false,
	}
	txHex, err := cfd.CfdGoAddTxPubkeyHashSign(t.network.ToCfdValue(), tx.Hex, outpoint.Txid, outpoint.Vout, hashType.ToCfdValue(), pubkey.Hex, signParam)
	if err != nil {
		return errors.Wrap(err, "CT.AddPubkeySign error")
	}
	tx.Hex = txHex
	return nil
}

// AddPubkeySignByDescriptor ...
func (t *ConfidentialTxApiImpl) AddPubkeySignByDescriptor(tx *types.ConfidentialTx, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error {
	var err error
	if err = t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	data, _, _, err := t.descriptorApi.Parse(outputDescriptor)
	if err != nil {
		return errors.Wrap(err, "parse descriptor error")
	}
	if data.HashType != int(cfd.KCfdP2pkh) && data.HashType != int(cfd.KCfdP2wpkh) && data.HashType != int(cfd.KCfdP2shP2wpkh) {
		return errors.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
	}

	hashType := types.NewHashType(data.HashType)
	var pubkey types.Pubkey
	if data.KeyType == int(cfd.KCfdDescriptorKeyPublic) {
		pubkey.Hex = data.Pubkey
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return errors.Wrap(err, "get pubkey error")
		}
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32Priv) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return errors.Wrap(err, "get pubkey error")
		}
	} else {
		return errors.Errorf("CFD Error: Descriptor keyType is not pubkeyHash")
	}
	return t.AddPubkeySign(tx, outpoint, hashType, &pubkey, signature)
}

// VerifySign ...
func (t *ConfidentialTxApiImpl) VerifySign(tx *types.ConfidentialTx, outpoint *types.OutPoint, txinUtxoList *[]types.ElementsUtxoData) (isVerify bool, reason string, err error) {
	if err := t.validConfig(); err != nil {
		return false, "", errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	lbtcAsset, _ := t.getDefaultBitcoinData()
	utxoList := []cfd.CfdUtxo{}
	if txinUtxoList != nil {
		utxoList = make([]cfd.CfdUtxo, len(*txinUtxoList))
		for i, utxo := range *txinUtxoList {
			utxoList[i] = utxo.ConvertToCfdUtxo()
			if len(utxo.Asset) == 0 {
				utxoList[i].Asset = lbtcAsset
			}
		}
	}
	if isVerify, reason, err = cfd.CfdGoVerifySign(t.network.ToCfdValue(), tx.Hex, utxoList, outpoint.Txid, outpoint.Vout); err != nil {
		return false, "", errors.Wrap(err, "verify error")
	}
	return isVerify, reason, nil
}

// GetTxid ...
func (t *ConfidentialTxApiImpl) GetTxid(tx *types.ConfidentialTx) string {
	if err := t.validConfig(); err != nil {
		return ""
	}
	handle, err := cfd.CfdGoInitializeTxDataHandle(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return ""
	}
	defer cfd.CfdGoFreeTxDataHandle(handle)

	data, err := cfd.CfdGoGetTxInfoByHandle(handle)
	if err != nil {
		return ""
	}
	return data.Txid
}

// GetPegoutAddress ...
func (t *ConfidentialTxApiImpl) GetPegoutAddress(tx *types.ConfidentialTx, index uint32) (pegoutAddress *types.Address, isPegoutOutput bool, err error) {
	if err := t.validConfig(); err != nil {
		return nil, false, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	addr, isPegoutOutput, err := cfd.CfdGoGetPegoutAddressFromTransaction(t.network.ToCfdValue(), tx.Hex, index, t.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, false, errors.Wrap(err, "get pegout address error")
	}
	pegoutAddress, err = t.bitcoinAddressApi.ParseAddress(addr)
	if err != nil {
		return nil, false, errors.Wrap(err, "parse address error")
	}
	return pegoutAddress, isPegoutOutput, nil
}

// GetSighash ...
func (t *ConfidentialTxApiImpl) GetSighash(tx *types.ConfidentialTx, outpoint *types.OutPoint, sighashType types.SigHashType, utxoList *[]types.ElementsUtxoData) (sighash *types.ByteData, err error) {
	if err := t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if utxoList == nil {
		return nil, errors.Errorf("CFD Error: utxoList is nil")
	}
	cfdNetType := t.network.ToCfdValue()
	var script *cfd.Script
	var pubkey *cfd.ByteData

	lbtcAsset, _ := t.getDefaultBitcoinData()
	txinUtxoList := make([]cfd.CfdUtxo, len(*utxoList))
	for i, utxo := range *utxoList {
		txinUtxoList[i] = utxo.ConvertToCfdUtxo()
		if len(utxo.Asset) == 0 {
			txinUtxoList[i].Asset = lbtcAsset
		}
		if utxo.OutPoint.Equal(*outpoint) {
			desc := t.descriptorApi.NewDescriptorFromString(utxo.Descriptor)
			if desc == nil {
				return nil, errors.Errorf("CFD Error: Invalid descriptor string")
			}
			data, _, _, err := t.descriptorApi.Parse(desc)
			if err != nil {
				return nil, errors.Wrap(err, "parse descriptor error")
			}

			if data.HashType != int(cfd.KCfdP2pkh) && data.HashType != int(cfd.KCfdP2wpkh) && data.HashType != int(cfd.KCfdP2shP2wpkh) {
				return nil, errors.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
			}
			if data.KeyType == int(cfd.KCfdDescriptorKeyPublic) {
				pubkey = cfd.NewByteDataFromHexIgnoreError(data.Pubkey)
			} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32) {
				tempPubkey, err := cfd.CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.network.ToBitcoinType().ToCfdValue())
				if err != nil {
					return nil, errors.Wrap(err, "get pubkey error")
				}
				pubkey = cfd.NewByteDataFromHexIgnoreError(tempPubkey)
			} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32Priv) {
				tempPubkey, err := cfd.CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.network.ToBitcoinType().ToCfdValue())
				if err != nil {
					return nil, errors.Wrap(err, "get pubkey error")
				}
				pubkey = cfd.NewByteDataFromHexIgnoreError(tempPubkey)
			} else if len(data.RedeemScript) != 0 {
				script = cfd.NewScriptFromHexIgnoreError(data.RedeemScript)
			} else {
				return nil, errors.Errorf("CFD Error: Descriptor invalid")
			}
			break
		}
	}
	cfdSighashType := cfd.SigHashType{
		Type:         sighashType.Type,
		AnyoneCanPay: sighashType.AnyoneCanPay,
		Rangeproof:   sighashType.Rangeproof,
	}
	sighashHex, err := cfd.CfdGoGetSighash(cfdNetType, tx.Hex, txinUtxoList, outpoint.Txid, outpoint.Vout, &cfdSighashType, pubkey, script, nil, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "get sighash error")
	}
	sighash = types.NewByteDataFromHexIgnoreError(sighashHex)
	return sighash, nil
}

func (t *ConfidentialTxApiImpl) FilterUtxoByTxInList(tx *types.ConfidentialTx, utxoList *[]types.ElementsUtxoData) (txinUtxoList []types.ElementsUtxoData, err error) {
	if err := t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	utxoMap := make(map[types.OutPoint]*types.ElementsUtxoData, len(*utxoList))
	for _, utxo := range *utxoList {
		utxoMap[utxo.OutPoint] = &utxo
	}

	_, cfdTxins, _, err := cfd.GetConfidentialTxData(tx.Hex, false)
	if err != nil {
		return nil, errors.Wrap(err, "parse tx error")
	}
	txinUtxos := make([]types.ElementsUtxoData, len(cfdTxins))
	for i, txin := range cfdTxins {
		outpoint := types.OutPoint{Txid: txin.OutPoint.Txid, Vout: txin.OutPoint.Vout}
		utxo, ok := utxoMap[outpoint]
		if !ok {
			return nil, errors.Errorf("CFD Error: txin is not found on utxoList")
		}
		txinUtxos[i] = *utxo
	}
	return txinUtxos, nil
}

// GetAll ...
func (t *ConfidentialTxApiImpl) GetAll(tx *types.ConfidentialTx, hasWitness bool) (data *types.TransactionData, txinList []types.ConfidentialTxIn, txoutList []types.ConfidentialTxOut, err error) {
	if err := t.validConfig(); err != nil {
		return nil, nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	cfdData, cfdTxins, cfdTxouts, err := cfd.GetConfidentialTxData(tx.Hex, hasWitness)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parse tx error")
	}
	return convertListData(&cfdData, cfdTxins, cfdTxouts)
}

func (t *ConfidentialTxApiImpl) GetTxIn(txHex string, outpoint *types.OutPoint) (txin *types.ConfidentialTxIn, err error) {
	handle, err := cfd.CfdGoInitializeTxDataHandle(types.LiquidV1.ToCfdValue(), txHex)
	if err != nil {
		return nil, errors.Wrap(err, "init tx error")
	}
	defer cfd.CfdGoFreeTxDataHandle(handle)

	var tempTxin types.ConfidentialTxIn
	index, err := cfd.CfdGoGetTxInIndexByHandle(handle, outpoint.Txid, outpoint.Vout)
	if err != nil {
		return nil, errors.Wrapf(err, "get txin index error(%s)", outpoint.String())
	}
	txid, vout, sequence, scriptSig, err := cfd.CfdGoGetTxInByHandle(handle, index)
	if err != nil {
		return nil, errors.Wrapf(err, "get txin error(%d)", index)
	}
	entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err := cfd.CfdGoGetTxInIssuanceInfoByHandle(handle, index)
	if err != nil {
		return nil, errors.Wrapf(err, "get txin issuance error(%d)", index)
	}

	tempTxin.OutPoint.Txid = txid
	tempTxin.OutPoint.Vout = vout
	tempTxin.Sequence = sequence
	tempTxin.ScriptSig = scriptSig
	if len(assetValue) > 2 {
		tempTxin.Issuance.Entropy = entropy
		tempTxin.Issuance.Nonce = nonce
		tempTxin.Issuance.AssetAmount = assetAmount
		tempTxin.Issuance.AssetValue = assetValue
		tempTxin.Issuance.TokenAmount = tokenAmount
		tempTxin.Issuance.TokenValue = tokenValue
		tempTxin.IssuanceAmountRangeproof = assetRangeproof
		tempTxin.InflationKeysRangeproof = tokenRangeproof
	}

	wCount, err := cfd.CfdGoGetTxInWitnessCountByHandle(handle, int(cfd.KCfdTxWitnessStackNormal), index)
	if err != nil {
		return nil, errors.Wrapf(err, "get txin witness count error(%d)", index)
	}
	wList := make([]string, wCount)
	for j := uint32(0); j < wCount; j++ {
		stackData, err := cfd.CfdGoGetTxInWitnessByHandle(handle, int(cfd.KCfdTxWitnessStackNormal), index, j)
		if err != nil {
			return nil, errors.Wrapf(err, "get txin witness count error(%d, %d)", index, j)
		}
		wList[j] = stackData
	}
	tempTxin.WitnessStack.Stack = wList

	pCount, err := cfd.CfdGoGetTxInWitnessCountByHandle(handle, int(cfd.KCfdTxWitnessStackPegin), index)
	if err != nil {
		return nil, errors.Wrapf(err, "get txin witness count error(%d)", index)
	}
	pList := make([]string, pCount)
	for j := uint32(0); j < pCount; j++ {
		stackData, err := cfd.CfdGoGetTxInWitnessByHandle(handle, int(cfd.KCfdTxWitnessStackPegin), index, j)
		if err != nil {
			return nil, errors.Wrapf(err, "get txin witness count error(%d, %d)", index, j)
		}
		pList[j] = stackData
	}
	tempTxin.PeginWitness.Stack = pList

	txin = &tempTxin
	return txin, nil
}

func convertListData(cfdData *cfd.TransactionData, cfdTxinList []cfd.ConfidentialTxIn, cfdTxoutList []cfd.ConfidentialTxOut) (data *types.TransactionData, txinList []types.ConfidentialTxIn, txoutList []types.ConfidentialTxOut, err error) {
	data = &types.TransactionData{
		Txid:     cfdData.Txid,
		Wtxid:    cfdData.Wtxid,
		WitHash:  cfdData.WitHash,
		Size:     cfdData.Size,
		Vsize:    cfdData.Vsize,
		Weight:   cfdData.Weight,
		Version:  cfdData.Version,
		LockTime: cfdData.LockTime,
	}
	txinList = make([]types.ConfidentialTxIn, len(cfdTxinList))
	for i, txin := range cfdTxinList {
		txinList[i] = *types.NewConfidentialTxIn(&txin)
	}
	txoutList = make([]types.ConfidentialTxOut, len(cfdTxoutList))
	for i, txout := range cfdTxoutList {
		txoutList[i] = *types.NewConfidentialTxOut(&txout)
	}
	return data, txinList, txoutList, nil
}

//func (t *ConfidentialTx) AddMultisigSign() error {
// FIXME need implements
//}

func (t *ConfidentialTxApiImpl) getDefaultBitcoinData() (lbtcAssetId, genesisBlockHash string) {
	conf := t.getConfig()
	return conf.BitcoinAssetId, conf.BitcoinGenesisBlockHash
}

// appendDummyOutput ...
func appendDummyOutput(txHex string, network types.NetworkType, txinList *[]types.BlindInputData) (outputTx string, err error) {
	var blindTxInCount uint32
	var blindTxOutCount uint32
	outputTx = txHex
	// get all list
	_, _, txoutList, err := cfd.GetConfidentialTxDataAll(txHex, false, false, network.ToCfdValue())
	if err != nil {
		return "", errors.Wrap(err, "get tx error")
	}

	if txinList != nil {
		for _, txin := range *txinList {
			if len(txin.ValueBlindFactor) == 64 && txin.ValueBlindFactor != EmptyBlinder {
				blindTxInCount += 1
			}
		}
	}

	var feeAsset string
	for _, txout := range txoutList {
		if len(txout.LockingScript) == 0 {
			feeAsset = txout.Asset // fee
		} else if len(txout.LockingScript) > 68 && strings.HasPrefix(txout.LockingScript, "6a") {
			// pegout
		} else if len(txout.CommitmentNonce) == 66 {
			blindTxOutCount += 1 // set confidential key
		}
		// TODO(k-matsuzawa): Should we also count Outputs that directly specify Nonce?
	}

	if (blindTxInCount + blindTxOutCount) == 1 {
		// generate random confidential key
		nonce, _, _, err := cfd.CfdGoCreateKeyPair(true, network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return "", errors.Wrap(err, "create keyPair error")
		}
		outputTx, err = cfd.CfdGoAddConfidentialTxOut(txHex, feeAsset, 0, "", "", "6a", nonce)
		if err != nil {
			return "", errors.Wrap(err, "add txout error")
		} else if outputTx == txHex {
			return "", errors.Errorf("CFD Error: fail logic")
		}
	} else if (blindTxInCount + blindTxOutCount) == 0 {
		return "", errors.Errorf("CFD Error: blinding in/out not found")
	}
	return outputTx, nil
}

// addConidentialTx ...
func (t *ConfidentialTxApiImpl) addConidentialTx(txHandle uintptr, network types.NetworkType, locktime uint32, txinList *[]types.InputConfidentialTxIn, txoutList *[]types.InputConfidentialTxOut, pegoutAddressList *[]string) (err error) {
	lbtcAsset, bitcoinGenesisBlockHash := t.getDefaultBitcoinData()

	if txinList != nil {
		var bitcoinTxOut *types.TxOut
		for i := 0; i < len(*txinList); i++ {
			seq := (*txinList)[i].Sequence
			if seq == 0 {
				if locktime == 0 {
					seq = uint32(cfd.KCfdSequenceLockTimeFinal)
				} else {
					seq = uint32(cfd.KCfdSequenceLockTimeEnableMax)
				}
			}
			if (*txinList)[i].PeginInput != nil {
				btcTx := types.Transaction{Hex: (*txinList)[i].PeginInput.BitcoinTransaction}
				bitcoinTxOut, err = t.bitcoinTxApi.GetTxOut(&btcTx, (*txinList)[i].OutPoint.Vout)
				if err != nil {
					return errors.Wrap(err, "get txout error")
				}
				asset := (*txinList)[i].PeginInput.BitcoinAssetId
				if len(asset) == 0 {
					asset = lbtcAsset
				}
				genesisBlockHash := (*txinList)[i].PeginInput.BitcoinGenesisBlockHash
				if len(genesisBlockHash) == 0 {
					genesisBlockHash = bitcoinGenesisBlockHash
				}
				err = cfd.AddPeginInput(txHandle,
					(*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout,
					bitcoinTxOut.Amount, asset, genesisBlockHash,
					(*txinList)[i].PeginInput.ClaimScript,
					(*txinList)[i].PeginInput.BitcoinTransaction,
					(*txinList)[i].PeginInput.TxOutProof,
				)
				if err == nil && (*txinList)[i].Sequence != 0 {
					err = cfd.UpdateTxInSequence(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
				}
			} else {
				err = cfd.AddTransactionInput(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
			}
			if err != nil {
				return errors.Wrap(err, "add txin error")
			}
		}
	}

	if txoutList != nil {
		for i := 0; i < len(*txoutList); i++ {
			asset := (*txoutList)[i].Asset
			if len(asset) == 0 {
				asset = lbtcAsset
			}
			if (*txoutList)[i].PegoutInput != nil {
				var pubkey string
				if len((*txoutList)[i].PegoutInput.OnlineKey) == 64 {
					pubkey, err = cfd.CfdGoGetPubkeyFromPrivkey((*txoutList)[i].PegoutInput.OnlineKey, "", true)
				} else {
					pubkey, err = cfd.CfdGoGetPubkeyFromPrivkey("", (*txoutList)[i].PegoutInput.OnlineKey, true)
				}
				if err != nil {
					return errors.Wrap(err, "get pubkey error")
				}
				genesisBlockHash := (*txoutList)[i].PegoutInput.BitcoinGenesisBlockHash
				if len(genesisBlockHash) == 0 {
					genesisBlockHash = bitcoinGenesisBlockHash
				}
				mainchainAddress, err := cfd.AddPegoutOutput(
					txHandle, asset, (*txoutList)[i].Amount,
					network.ToBitcoinType().ToCfdValue(), network.ToCfdValue(),
					genesisBlockHash, pubkey, (*txoutList)[i].PegoutInput.OnlineKey,
					(*txoutList)[i].PegoutInput.BitcoinOutputDescriptor,
					(*txoutList)[i].PegoutInput.Bip32Counter,
					(*txoutList)[i].PegoutInput.Whitelist)
				if pegoutAddressList != nil && err == nil {
					*pegoutAddressList = append(*pegoutAddressList, mainchainAddress)
				}
			} else if (*txoutList)[i].IsDestroy {
				err = cfd.AddTransactionOutput(txHandle, (*txoutList)[i].Amount, "", "6a", asset)
			} else if (*txoutList)[i].IsFee {
				err = cfd.AddTransactionOutput(txHandle, (*txoutList)[i].Amount, "", "", asset)
			} else {
				err = cfd.AddTransactionOutput(txHandle, (*txoutList)[i].Amount, (*txoutList)[i].Address, (*txoutList)[i].LockingScript, asset)
			}
			if err != nil {
				return errors.Wrap(err, "get txout error")
			}
		}
	}
	return nil
}

func updateDirectNonce(txHandle uintptr, txHex string, txoutList *[]types.InputConfidentialTxOut) (outputTxHex string, err error) {
	count := 0
	for i := 0; i < len(*txoutList); i++ {
		if len((*txoutList)[i].Nonce) == types.CommitmentHexDataSize {
			count += 1
		}
	}
	if count == 0 {
		return txHex, nil
	}

	outputTxHex = txHex
	for i := 0; i < len(*txoutList); i++ {
		if len((*txoutList)[i].Nonce) != types.CommitmentHexDataSize {
			// do nothing
		} else if ((*txoutList)[i].PegoutInput != nil) || (*txoutList)[i].IsFee || (len((*txoutList)[i].Address) > 0) {
			// do nothing
		} else if (*txoutList)[i].IsDestroy || (len((*txoutList)[i].LockingScript) > 0) {
			asset, satoshiAmount, valueCommitment, _, lockingScript, err := cfd.CfdGoGetConfidentialTxOutSimpleByHandle(txHandle, uint32(i))
			if err != nil {
				return "", errors.Wrapf(err, "get txout error(%d)", i)
			}
			outputTxHex, err = cfd.CfdGoUpdateConfidentialTxOut(outputTxHex, uint32(i), asset, satoshiAmount, valueCommitment, "", lockingScript, (*txoutList)[i].Nonce)
			if err != nil {
				return "", errors.Wrapf(err, "update txout error(%d)", i)
			}
		}
	}
	return outputTxHex, nil
}
