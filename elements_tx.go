package cfdgo

import (
	"fmt"
	"strings"
	"unsafe"
)

const (
	EmptyBlinder string = "0000000000000000000000000000000000000000000000000000000000000000"
)

// -------------------------------------
// API struct
// -------------------------------------

// ConfidentialTx The confidential transaction.
type ConfidentialTx struct {
	Hex     string
	Network NetworkType
}

// ElementsTransactionUtil Create confidential transaction utility.
type ElementsTransactionUtil struct {
	Network *NetworkType
}

// -------------------------------------
// Data struct
// -------------------------------------

// IssuanceData confidential transaction issuance input.
type IssuanceData struct {
	Entropy     string
	Nonce       string
	AssetAmount int64
	AssetValue  string
	TokenAmount int64
	TokenValue  string
}

// ConfidentialTxIn confidential transaction input.
type ConfidentialTxIn struct {
	OutPoint                 OutPoint
	Sequence                 uint32
	ScriptSig                string
	Issuance                 IssuanceData
	WitnessStack             ScriptWitness
	PeginWitness             ScriptWitness
	IssuanceAmountRangeproof string
	InflationKeysRangeproof  string
}

// ConfidentialTxOut confidential transaction output.
type ConfidentialTxOut struct {
	Amount          int64  // satoshi amount (unblind value)
	Asset           string // asset (or commitment asset)
	LockingScript   string // locking script
	Address         string // address or confidential address. (if locking script is usual hashtype.)
	CommitmentValue string // commitment value
	CommitmentNonce string // commitment nonce
	Surjectionproof string // surjectionprooof of asset
	Rangeproof      string // rangeproof of value
}

// InputConfidentialTxIn ...
type InputConfidentialTxIn struct {
	OutPoint   OutPoint
	Sequence   uint32
	PeginInput *InputPeginData
}

// InputConfidentialTxOut ...
type InputConfidentialTxOut struct {
	Amount        int64  // satoshi amount (unblind value)
	Asset         string // asset (or commitment asset)
	LockingScript string // locking script
	Address       string // address or confidential address. (if locking script is usual hashtype.)
	Nonce         string // direct nonce
	PegoutInput   *InputPegoutData
	IsDestroy     bool
	IsFee         bool
}

// InputPeginData ...
type InputPeginData struct {
	BitcoinTransaction      string
	BitcoinGenesisBlockHash string
	BitcoinAssetId          string
	ClaimScript             string
	TxOutProof              string
}

// InputPegoutData ...
type InputPegoutData struct {
	BitcoinGenesisBlockHash string
	OnlineKey               string
	BitcoinOutputDescriptor string
	Bip32Counter            uint32
	Whitelist               string
}

// IssuanceBlindingKey ...
type IssuanceBlindingKey struct {
	AssetBlindingKey string // (option) Asset blinding key
	TokenBlindingKey string // (option) Token blinding key
}

// BlindInputData ...
type BlindInputData struct {
	OutPoint         OutPoint // OutPoint
	Asset            string   // Asset
	AssetBlindFactor string   // Asset BlindFactor
	Amount           int64    // satoshi value
	ValueBlindFactor string   // Value BlindFactor
	IssuanceKey      *IssuanceBlindingKey
}

// BlindOutputData ...
type BlindOutputData struct {
	Index               int    // txout index (-1: auto)
	ConfidentialAddress string // confidential or not address
	ConfidentialKey     string // (optional) confidential key
}

// BlindTxOption BlindRawTransaction option data struct.
type BlindTxOption struct {
	MinimumRangeValue int64 // blind minimum range value
	Exponent          int64 // blind exponent
	MinimumBits       int64 // blind minimum bits
	AppendDummyOutput bool  // add dummy output if txout is low
}

// -------------------------------------
// BlindTxOption
// -------------------------------------
// NewBlindTxOption ...
func NewBlindTxOption() BlindTxOption {
	option := BlindTxOption{}
	option.MinimumRangeValue = int64(1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	option.AppendDummyOutput = false
	return option
}

// -------------------------------------
// ElementsTransactionUtil
// -------------------------------------

func (u *ElementsTransactionUtil) Create(version uint32, locktime uint32, txinList *[]InputConfidentialTxIn, txoutList *[]InputConfidentialTxOut, pegoutAddressList *[]string) (tx *ConfidentialTx, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	txHandle, err := InitializeTransaction(u.Network.ToCfdValue(), version, locktime)
	if err != nil {
		return nil, err
	}
	defer FreeTransactionHandle(txHandle)

	if err = addConidentialTx(txHandle, *u.Network, locktime, txinList, txoutList, pegoutAddressList); err != nil {
		return nil, err
	}

	txHex, err := internalFinalizeTransaction(txHandle)
	if err != nil {
		return nil, err
	}
	return &ConfidentialTx{Hex: txHex, Network: *u.Network}, nil
}

func (u *ElementsTransactionUtil) validConfig() error {
	if u.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		netType := cfdConfig.Network
		u.Network = &netType
	}
	if !u.Network.IsElements() {
		return fmt.Errorf("CFD Error: NetworkType is not elements")
	}
	return nil
}

// -------------------------------------
// ConfidentialTx
// -------------------------------------

func (t *ConfidentialTx) Add(txinList *[]InputConfidentialTxIn, txoutList *[]InputConfidentialTxOut, pegoutAddressList *[]string) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	txHandle, err := InitializeTransactionByHex(t.Network.ToCfdValue(), t.Hex)
	if err != nil {
		return err
	}
	defer FreeTransactionHandle(txHandle)

	data, err := CfdGoGetConfidentialTxDataByHandle(txHandle)
	if err != nil {
		return err
	}

	if err = addConidentialTx(txHandle, t.Network, data.LockTime, txinList, txoutList, pegoutAddressList); err != nil {
		return err
	}

	txHex, err := internalFinalizeTransaction(txHandle)
	if err != nil {
		return err
	}
	t.Hex = txHex
	return nil
}

//func (t *ConfidentialTx) SetReissueAsset() error {
// FIXME need implements
//}

// Blind ...
func (t *ConfidentialTx) Blind(txinList []BlindInputData, txoutList *[]BlindOutputData, option *BlindTxOption) error {
	lbtcAsset, _ := getDefaultBitcoinData()

	var err error
	if err = t.validConfig(); err != nil {
		return err
	}

	txHex := t.Hex
	if option != nil && option.AppendDummyOutput {
		// check & add txout
		txHex, err = appendDummyOutput(txHex, t.Network, &txinList)
		if err != nil {
			return err
		}
	}

	// convert list
	blindTxinList := make([]CfdBlindInputData, len(txinList))
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
	var blindOutputList []CfdBlindOutputData
	if txoutList != nil {
		blindOutputList = *(*[]CfdBlindOutputData)(unsafe.Pointer(txoutList))
	}
	blindOption := (*CfdBlindTxOption)(unsafe.Pointer(option))
	outputTx, err := CfdGoBlindRawTransaction(txHex, blindTxinList, blindOutputList, blindOption)
	if err != nil {
		return err
	}
	t.Hex = outputTx
	return nil
}

// AddPubkeySign ...
func (t *ConfidentialTx) AddPubkeySign(outpoint *OutPoint, hashType HashType, pubkey *Pubkey, signature string) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	signParam := CfdSignParameter{
		Data:                signature,
		IsDerEncode:         false,
		SighashType:         int(KCfdSigHashAll),
		SighashAnyoneCanPay: false,
	}
	txHex, err := CfdGoAddTxPubkeyHashSign(t.Network.ToCfdValue(), t.Hex, outpoint.Txid, outpoint.Vout, hashType.ToCfdValue(), pubkey.Hex, signParam)
	if err == nil {
		t.Hex = txHex
	}
	return err
}

// AddPubkeySignByDescriptor ...
func (t *ConfidentialTx) AddPubkeySignByDescriptor(outpoint *OutPoint, descriptor *Descriptor, signature string) error {
	var err error
	if err = t.validConfig(); err != nil {
		return err
	}
	data, _, _, err := descriptor.Parse()
	if err != nil {
		return err
	}
	if data.HashType != int(KCfdP2pkh) && data.HashType != int(KCfdP2wpkh) && data.HashType != int(KCfdP2shP2wpkh) {
		return fmt.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
	}

	hashType := NewHashType(data.HashType)
	var pubkey Pubkey
	if data.KeyType == int(KCfdDescriptorKeyPublic) {
		pubkey.Hex = data.Pubkey
	} else if data.KeyType == int(KCfdDescriptorKeyBip32) {
		pubkey.Hex, err = CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.Network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return err
		}
	} else if data.KeyType == int(KCfdDescriptorKeyBip32Priv) {
		pubkey.Hex, err = CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.Network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("CFD Error: Descriptor keyType is not pubkeyHash")
	}
	return t.AddPubkeySign(outpoint, hashType, &pubkey, signature)
}

// VerifySign ...
func (t *ConfidentialTx) VerifySign(outpoint *OutPoint, amount int64, txinUtxoList *[]UtxoData) (isVerify bool, reason string, err error) {
	if err := t.validConfig(); err != nil {
		return false, "", err
	}
	lbtcAsset, _ := getDefaultBitcoinData()
	utxoList := (*[]CfdUtxo)(unsafe.Pointer(txinUtxoList))
	for i, utxo := range *utxoList {
		if len(utxo.Asset) == 0 {
			(*utxoList)[i].Asset = lbtcAsset
		}
	}
	return CfdGoVerifySign(t.Network.ToCfdValue(), t.Hex, *utxoList, outpoint.Txid, outpoint.Vout)
}

// GetTxid ...
func (t *ConfidentialTx) GetTxid() string {
	if err := t.validConfig(); err != nil {
		return ""
	}
	handle, err := CfdGoInitializeTxDataHandle(t.Network.ToCfdValue(), t.Hex)
	if err != nil {
		return ""
	}
	defer CfdGoFreeTxDataHandle(handle)

	data, err := CfdGoGetTxInfoByHandle(handle)
	if err != nil {
		return ""
	}
	return data.Txid
}

// GetPegoutAddress ...
func (t *ConfidentialTx) GetPegoutAddress(index uint32) (pegoutAddress *Address, isPegoutOutput bool, err error) {
	if err := t.validConfig(); err != nil {
		return nil, false, err
	}
	addr, isPegoutOutput, err := CfdGoGetPegoutAddressFromTransaction(t.Network.ToCfdValue(), t.Hex, index, t.Network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, false, err
	}
	btcNetwork := t.Network.ToBitcoinType()
	addrUtil := AddressUtil{Network: &btcNetwork}
	pegoutAddress, err = addrUtil.ParseAddress(addr)
	if err != nil {
		return nil, false, err
	}
	return pegoutAddress, isPegoutOutput, nil
}

// GetSighash ...
func (t *ConfidentialTx) GetSighash(outpoint *OutPoint, sighashType SigHashType, utxoList *[]UtxoData) (sighash *ByteData, err error) {
	if err := t.validConfig(); err != nil {
		return nil, err
	}
	cfdNetType := t.Network.ToCfdValue()
	var script *Script
	var pubkey *ByteData
	for _, utxo := range *utxoList {
		if utxo.Txid == outpoint.Txid && utxo.Vout == outpoint.Vout {
			desc := NewDescriptorFromString(utxo.Descriptor, cfdNetType)
			if desc == nil {
				return nil, fmt.Errorf("CFD Error: Invalid descriptor string")
			}
			data, _, _, err := desc.Parse()
			if err != nil {
				return nil, err
			}

			if data.HashType != int(KCfdP2pkh) && data.HashType != int(KCfdP2wpkh) && data.HashType != int(KCfdP2shP2wpkh) {
				return nil, fmt.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
			}
			if data.KeyType == int(KCfdDescriptorKeyPublic) {
				pubkey = NewByteDataFromHexIgnoreError(data.Pubkey)
			} else if data.KeyType == int(KCfdDescriptorKeyBip32) {
				tempPubkey, err := CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.Network.ToBitcoinType().ToCfdValue())
				if err != nil {
					return nil, err
				}
				pubkey = NewByteDataFromHexIgnoreError(tempPubkey)
			} else if data.KeyType == int(KCfdDescriptorKeyBip32Priv) {
				tempPubkey, err := CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.Network.ToBitcoinType().ToCfdValue())
				if err != nil {
					return nil, err
				}
				pubkey = NewByteDataFromHexIgnoreError(tempPubkey)
			} else if len(data.RedeemScript) != 0 {
				script = &Script{hex: data.RedeemScript}
			} else {
				return nil, fmt.Errorf("CFD Error: Descriptor invalid")
			}
			break
		}
	}
	lbtcAsset, _ := getDefaultBitcoinData()
	txinUtxoList := (*[]CfdUtxo)(unsafe.Pointer(utxoList))
	for i, utxo := range *txinUtxoList {
		if len(utxo.Asset) == 0 {
			(*txinUtxoList)[i].Asset = lbtcAsset
		}
	}
	sighashHex, err := CfdGoGetSighash(cfdNetType, t.Hex, *txinUtxoList, outpoint.Txid, outpoint.Vout, &sighashType, pubkey, script, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return NewByteDataFromHexIgnoreError(sighashHex), nil
}

// GetAll ...
func (t *ConfidentialTx) GetAll(hasWitness bool) (data TransactionData, txinList []ConfidentialTxIn, txoutList []ConfidentialTxOut, err error) {
	if err := t.validConfig(); err != nil {
		return data, txinList, txoutList, err
	}
	return GetConfidentialTxData(t.Hex, hasWitness)
}

//func (t *ConfidentialTx) AddMultisigSign() error {
// FIXME need implements
//}

func getDefaultBitcoinData() (lbtcAssetId, genesisBlockHash string) {
	if len(cfdConfig.BitcoinGenesisBlockHash) == 64 {
		genesisBlockHash = cfdConfig.BitcoinGenesisBlockHash
	}
	if len(cfdConfig.BitcoinAssetId) == 64 {
		lbtcAssetId = cfdConfig.BitcoinAssetId
	}
	return lbtcAssetId, genesisBlockHash
}

func (t *ConfidentialTx) validConfig() error {
	if t.Network == Unknown {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		t.Network = cfdConfig.Network
	}
	if !t.Network.IsElements() {
		return fmt.Errorf("CFD Error: NetworkType is not elements")
	}
	return nil
}

// low-layer API ---------------------------------------------------------------

// appendDummyOutput ...
func appendDummyOutput(txHex string, network NetworkType, txinList *[]BlindInputData) (outputTx string, err error) {
	var blindTxInCount uint32
	var blindTxOutCount uint32
	outputTx = txHex
	// get all list
	_, _, txoutList, err := GetConfidentialTxDataAll(txHex, false, false, network.ToCfdValue())
	if err != nil {
		return "", err
	}

	if txinList != nil {
		for _, txin := range *txinList {
			if len(txin.ValueBlindFactor) == 64 && txin.ValueBlindFactor != EmptyBlinder {
				blindTxInCount = blindTxInCount + 1
			}
		}
	}

	var feeAsset string
	for _, txout := range txoutList {
		if len(txout.LockingScript) == 0 {
			// fee
			feeAsset = txout.Asset
		} else if len(txout.LockingScript) > 68 && strings.HasPrefix(txout.LockingScript, "6a") {
			// pegout
		} else if len(txout.CommitmentNonce) == 66 {
			// set confidential key
			blindTxOutCount = blindTxOutCount + 1
		}
		// TODO(k-matsuzawa): Should we also count Outputs that directly specify Nonce?
	}

	if (blindTxInCount + blindTxOutCount) == 1 {
		// generate random confidential key
		nonce, _, _, err := CfdGoCreateKeyPair(true, network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return "", err
		}
		outputTx, err = CfdGoAddConfidentialTxOut(txHex, feeAsset, 0, "", "", "6a", nonce)
		if err != nil {
			return "", err
		}
		if outputTx == txHex {
			return "", fmt.Errorf("CFD Error: fail logic")
		}
	} else if (blindTxInCount + blindTxOutCount) == 0 {
		// invalid blinding.
		return "", fmt.Errorf("CFD Error: blinding in/out not found")
		//} else if (blindTxInCount + blindTxOutCount) == 2 {
		//return "", fmt.Errorf("CFD Error: in/out=%d/%d", blindTxInCount, blindTxOutCount)
	}
	return outputTx, nil
}

// addConidentialTx ...
func addConidentialTx(txHandle uintptr, network NetworkType, locktime uint32, txinList *[]InputConfidentialTxIn, txoutList *[]InputConfidentialTxOut, pegoutAddressList *[]string) error {
	lbtcAsset, bitcoinGenesisBlockHash := getDefaultBitcoinData()

	var err error
	if txinList != nil {
		var bitcoinTxOut *TxOut
		for i := 0; i < len(*txinList); i++ {
			seq := (*txinList)[i].Sequence
			if seq == 0 {
				if locktime == 0 {
					seq = uint32(KCfdSequenceLockTimeFinal)
				} else {
					seq = uint32(KCfdSequenceLockTimeEnableMax)
				}
			}
			if (*txinList)[i].PeginInput != nil {
				bitcoinTxOut, err = GetTxOut((*txinList)[i].PeginInput.BitcoinTransaction, (*txinList)[i].OutPoint.Vout, network.ToBitcoinType().ToCfdValue())
				if err != nil {
					return err
				}
				asset := (*txinList)[i].PeginInput.BitcoinAssetId
				if len(asset) == 0 {
					asset = lbtcAsset
				}
				genesisBlockHash := (*txinList)[i].PeginInput.BitcoinGenesisBlockHash
				if len(genesisBlockHash) == 0 {
					genesisBlockHash = bitcoinGenesisBlockHash
				}
				err = AddPeginInput(txHandle,
					(*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout,
					bitcoinTxOut.Amount, asset, genesisBlockHash,
					(*txinList)[i].PeginInput.ClaimScript,
					(*txinList)[i].PeginInput.BitcoinTransaction,
					(*txinList)[i].PeginInput.TxOutProof,
				)
				if err == nil && (*txinList)[i].Sequence != 0 {
					err = UpdateTxInSequence(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
				}
			} else {
				err = AddTransactionInput(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
			}
			if err != nil {
				return err
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
					pubkey, err = CfdGoGetPubkeyFromPrivkey((*txoutList)[i].PegoutInput.OnlineKey, "", true)
				} else {
					pubkey, err = CfdGoGetPubkeyFromPrivkey("", (*txoutList)[i].PegoutInput.OnlineKey, true)
				}
				if err != nil {
					return err
				}
				genesisBlockHash := (*txoutList)[i].PegoutInput.BitcoinGenesisBlockHash
				if len(genesisBlockHash) == 0 {
					genesisBlockHash = bitcoinGenesisBlockHash
				}
				mainchainAddress, err := AddPegoutOutput(
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
				err = AddTransactionOutput(txHandle, (*txoutList)[i].Amount, "", "6a", asset)
			} else if (*txoutList)[i].IsFee {
				err = AddTransactionOutput(txHandle, (*txoutList)[i].Amount, "", "", asset)
			} else {
				err = AddTransactionOutput(txHandle, (*txoutList)[i].Amount, (*txoutList)[i].Address, (*txoutList)[i].LockingScript, asset)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateConfidentialTx This function create confidential transaction.
func CreateConfidentialTx(version uint32, locktime uint32, txinList []ConfidentialTxIn, txoutList []ConfidentialTxOut) (outputTxHex string, err error) {
	outputTxHex = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var createTxHandle uintptr
	networkType := int(KCfdNetworkLiquidv1)
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeTransaction(handle, networkType, versionPtr, locktimePtr, "", &createTxHandle)
	if err = convertCfdError(ret, handle); err != nil {
		return
	}
	defer CfdFreeTransactionHandle(handle, createTxHandle)

	for i := 0; i < len(txinList); i++ {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinList[i].OutPoint.Vout)))
		sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinList[i].Sequence)))
		ret = CfdAddTransactionInput(handle, createTxHandle, txinList[i].OutPoint.Txid, voutPtr, sequencePtr)
		if ret != int(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	for i := 0; i < len(txoutList); i++ {
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txoutList[i].Amount)))
		if txoutList[i].Address == "" {
			ret = CfdAddTransactionOutput(handle, createTxHandle, amountPtr, "", txoutList[i].LockingScript, txoutList[i].Asset)
		} else {
			ret = CfdAddTransactionOutput(handle, createTxHandle, amountPtr, txoutList[i].Address, "", txoutList[i].Asset)
		}
		if ret != int(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	ret = CfdFinalizeTransaction(handle, createTxHandle, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

// AppendConfidentialTx : append confidential transaction.
// param: txHex         transaction hex.
// param: txinList      transaction input list.
// param: txoutList     transaction output list.
// return: outputTxHex  transaction hex.
// return: err          error
func AppendConfidentialTx(txHex string, txinList []ConfidentialTxIn, txoutList []ConfidentialTxOut) (outputTxHex string, err error) {
	outputTxHex = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	networkType := int(KCfdNetworkLiquidv1)
	createTxHandle := uintptr(0)
	version := 0
	locktime := 0
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeTransaction(handle, networkType, versionPtr, locktimePtr, txHex, &createTxHandle)
	if ret != int(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeTransactionHandle(handle, createTxHandle)

	for i := 0; i < len(txinList); i++ {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinList[i].OutPoint.Vout)))
		sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinList[i].Sequence)))
		ret = CfdAddTransactionInput(handle, createTxHandle, txinList[i].OutPoint.Txid, voutPtr, sequencePtr)
		if ret != int(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	for i := 0; i < len(txoutList); i++ {
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txoutList[i].Amount)))
		if txoutList[i].Address == "" {
			ret = CfdAddTransactionOutput(handle, createTxHandle, amountPtr, "", txoutList[i].LockingScript, txoutList[i].Asset)
		} else {
			ret = CfdAddTransactionOutput(handle, createTxHandle, amountPtr, txoutList[i].Address, "", txoutList[i].Asset)
		}
		if ret != int(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	ret = CfdFinalizeTransaction(handle, createTxHandle, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

func GetConfidentialTxData(txHex string, hasWitness bool) (data TransactionData, txinList []ConfidentialTxIn, txoutList []ConfidentialTxOut, err error) {
	data, txinList, txoutList, err = GetConfidentialTxDataAll(txHex, hasWitness, false, int(KCfdNetworkLiquidv1))
	return
}

func GetConfidentialTxDataAll(txHex string, hasWitness bool, hasAddress bool, networkType int) (data TransactionData, txinList []ConfidentialTxIn, txoutList []ConfidentialTxOut, err error) {
	handle, err := CfdGoInitializeTxDataHandle(networkType, txHex)
	if err != nil {
		return data, txinList, txoutList, err
	}
	defer CfdGoFreeTxDataHandle(handle)

	tempData, err := CfdGoGetConfidentialTxDataByHandle(handle)
	if err != nil {
		return data, txinList, txoutList, err
	}
	txinCount, err := CfdGoGetTxInCountByHandle(handle)
	if err != nil {
		return data, txinList, txoutList, err
	}
	txoutCount, err := CfdGoGetTxOutCountByHandle(handle)
	if err != nil {
		return data, txinList, txoutList, err
	}

	tempTxins := make([]ConfidentialTxIn, txinCount)
	for i := uint32(0); i < txinCount; i++ {
		txid, vout, sequence, scriptSig, err := CfdGoGetTxInByHandle(handle, i)
		if err != nil {
			return data, txinList, txoutList, err
		}

		entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err := CfdGoGetTxInIssuanceInfoByHandle(handle, i)
		if err != nil {
			return data, txinList, txoutList, err
		}

		tempTxins[i].OutPoint.Txid = txid
		tempTxins[i].OutPoint.Vout = vout
		tempTxins[i].Sequence = sequence
		tempTxins[i].ScriptSig = scriptSig
		if len(assetValue) > 2 {
			tempTxins[i].Issuance.Entropy = entropy
			tempTxins[i].Issuance.Nonce = nonce
			tempTxins[i].Issuance.AssetAmount = assetAmount
			tempTxins[i].Issuance.AssetValue = assetValue
			tempTxins[i].Issuance.TokenAmount = tokenAmount
			tempTxins[i].Issuance.TokenValue = tokenValue
			if hasWitness {
				tempTxins[i].IssuanceAmountRangeproof = assetRangeproof
				tempTxins[i].InflationKeysRangeproof = tokenRangeproof
			}
		}

		if hasWitness {
			wCount, err := CfdGoGetTxInWitnessCountByHandle(handle, 0, i)
			if err != nil {
				return data, txinList, txoutList, err
			}
			wList := make([]string, txinCount)
			for j := uint32(0); j < wCount; j++ {
				stackData, err := CfdGoGetTxInWitnessByHandle(handle, 0, i, j)
				if err != nil {
					return data, txinList, txoutList, err
				}
				wList[j] = stackData
			}
			tempTxins[i].WitnessStack.Stack = wList

			pCount, err := CfdGoGetTxInWitnessCountByHandle(handle, 1, i)
			if err != nil {
				return data, txinList, txoutList, err
			}
			pList := make([]string, pCount)
			for j := uint32(0); j < wCount; j++ {
				stackData, err := CfdGoGetTxInWitnessByHandle(handle, 1, i, j)
				if err != nil {
					return data, txinList, txoutList, err
				}
				wList[j] = stackData
			}
			tempTxins[i].PeginWitness.Stack = pList
		}
	}

	tempTxouts := make([]ConfidentialTxOut, txoutCount)
	for i := uint32(0); i < txoutCount; i++ {
		var lockingScript string

		if hasWitness {
			asset, satoshiAmount, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err := CfdGoGetConfidentialTxOutByHandle(handle, i)
			if err != nil {
				return data, txinList, txoutList, err
			}
			tempTxouts[i].Amount = satoshiAmount
			tempTxouts[i].Asset = asset
			tempTxouts[i].CommitmentValue = valueCommitment
			tempTxouts[i].CommitmentNonce = nonce
			tempTxouts[i].LockingScript = lockingScript
			tempTxouts[i].Surjectionproof = surjectionProof
			tempTxouts[i].Rangeproof = rangeproof
		} else {
			asset, satoshiAmount, valueCommitment, nonce, lockingScript, err := CfdGoGetConfidentialTxOutSimpleByHandle(handle, i)
			if err != nil {
				return data, txinList, txoutList, err
			}
			tempTxouts[i].Amount = satoshiAmount
			tempTxouts[i].Asset = asset
			tempTxouts[i].CommitmentValue = valueCommitment
			tempTxouts[i].CommitmentNonce = nonce
			tempTxouts[i].LockingScript = lockingScript
		}
		if hasAddress {
			addr, err := CfdGoGetAddressFromLockingScript(lockingScript, networkType)
			if err != nil {
				return data, txinList, txoutList, err
			}
			tempTxouts[i].Address = addr
		}
	}

	data.Txid = tempData.Txid
	data.Wtxid = tempData.Wtxid
	data.WitHash = tempData.WitHash
	data.Size = tempData.Size
	data.Vsize = tempData.Vsize
	data.Weight = tempData.Weight
	data.Version = tempData.Version
	data.LockTime = tempData.LockTime
	txinList = tempTxins
	txoutList = tempTxouts
	return data, txinList, txoutList, nil
}

// SplitConfidentialTxOut This function set the split outputs.
func SplitConfidentialTxOut(createTxHandle uintptr, index uint32, txouts []CfdConfidentialTxOut) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	splitTxHandle := uintptr(0)
	ret := CfdCreateSplitTxOutHandle(handle, createTxHandle, &splitTxHandle)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}
	defer CfdFreeSplitTxOutHandle(handle, splitTxHandle)

	for _, txout := range txouts {
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txout.Amount)))
		ret := CfdAddSplitTxOutData(handle, splitTxHandle, amountPtr, txout.Address, txout.LockingScript, txout.CommitmentNonce)
		if err = convertCfdError(ret, handle); err != nil {
			return err
		}
	}

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret = CfdSplitTxOut(handle, createTxHandle, splitTxHandle, indexPtr)
	return convertCfdError(ret, handle)
}

// SetReissueAsset This function set a reissuance information.
func SetReissueAsset(createTxHandle uintptr, txid string, vout uint32, assetSatoshiAmount int64, blindingNonce string, entropy string, address string, directLockingScript string) (asset string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetSatoshiAmount)))
	ret := CfdSetReissueAsset(handle, createTxHandle, txid, voutPtr, satoshiPtr, blindingNonce, entropy, address, directLockingScript, &asset)
	err = convertCfdError(ret, handle)
	return asset, err
}

// AddPeginInput This function add a pegin input.
func AddPeginInput(createTxHandle uintptr, txid string, vout uint32, amount int64, asset, mainchainGenesisBlockHash, claimScript, mainchainTxHex, txoutProof string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdAddTxPeginInput(handle, createTxHandle, txid, voutPtr, amountPtr, asset, mainchainGenesisBlockHash, claimScript, mainchainTxHex, txoutProof)
	return convertCfdError(ret, handle)
}

// AddPegoutOutput This function add a pegout output.
func AddPegoutOutput(createTxHandle uintptr, asset string, amount int64, mainchainNetworkType, elementsNetworkType int, mainchainGenesisBlockHash, onlinePubkey, masterOnlineKey, mainchainOutputDescriptor string, bip32Counter uint32, whitelist string) (mainchainAddress string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	bip32CounterPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&bip32Counter)))
	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdAddTxPegoutOutput(handle, createTxHandle, asset, amountPtr,
		mainchainNetworkType, elementsNetworkType, mainchainGenesisBlockHash, onlinePubkey, masterOnlineKey, mainchainOutputDescriptor, bip32CounterPtr, whitelist, &mainchainAddress)
	err = convertCfdError(ret, handle)
	return
}

// HasPegoutOutput This function check pegout output.
func HasPegoutOutput(createTxHandle uintptr, index uint32) (hasPegout bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdHasPegoutConfidentialTxOut(handle, createTxHandle, indexPtr)
	if ret == int(KCfdSuccess) {
		hasPegout = true
	} else {
		hasPegout = false
		if ret != (int)(KCfdNotFoundError) {
			err = convertCfdError(ret, handle)
		}
	}
	return hasPegout, err
}

// GetPegoutAddressFromTransaction This function is getting pegout address from tx.
func GetPegoutAddressFromTransaction(createTxHandle uintptr, index uint32, mainchainNetwork int) (pegoutAddress string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetPegoutMainchainAddress(handle, createTxHandle, indexPtr, mainchainNetwork, &pegoutAddress)
	err = convertCfdError(ret, handle)
	return pegoutAddress, err
}

// SetIssueAsset This function set a issuance information.
func SetIssueAsset(createTxHandle uintptr, txid string, vout uint32, contractHash string, assetSatoshiAmount int64, assetAddress, assetLockingScript string, tokenSatoshiAmount int64, tokenAddress, tokenLockingScript string, isBlindAsset bool) (entropy, asset, token string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	assetSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetSatoshiAmount)))
	tokenSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenSatoshiAmount)))
	ret := CfdSetIssueAsset(handle, createTxHandle, txid, voutPtr, contractHash, assetSatoshiPtr, assetAddress, assetLockingScript, tokenSatoshiPtr, tokenAddress, tokenLockingScript, isBlindAsset, &entropy, &asset, &token)
	err = convertCfdError(ret, handle)
	return entropy, asset, token, err
}

// UpdatePeginWitnessStack This function set a witness stack item.
func UpdatePeginWitnessStack(createTxHandle uintptr, txid string, vout uint32, witnessIndex uint32, data string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	witnessIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&witnessIndex)))
	ret := CfdUpdateWitnessStack(handle, createTxHandle, int(KCfdTxWitnessStackPegin), txid, voutPtr, witnessIndexPtr, data)
	return convertCfdError(ret, handle)
}
