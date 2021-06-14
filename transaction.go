package cfdgo

import (
	"fmt"
	"unsafe"
)

const (
	SequenceLockTimeFinal     uint32 = 0xffffffff
	SequenceLockTimeEnableMax uint32 = 0xfffffffe
)

// -------------------------------------
// API struct
// -------------------------------------

// ConfidentialTx : confidential transaction input.
type Transaction struct {
	Hex     string
	Network NetworkType
}

type TransactionUtil struct {
	Network *NetworkType
}

// -------------------------------------
// Data struct
// -------------------------------------

// OutPoint : utxo outpoint struct.
type OutPoint struct {
	// txid
	Txid string
	// vout
	Vout uint32
}

// ScriptWitness : witness stack.
type ScriptWitness struct {
	// witness stack by hex.
	Stack []string
}

// TxIn : transaction input.
type TxIn struct {
	// utxo outpoint.
	OutPoint OutPoint
	// sequence number.
	Sequence uint32
	// script sig.
	ScriptSig string
	// witness stack.
	WitnessStack ScriptWitness
}

// TxOut : transaction output.
type TxOut struct {
	// satoshi amount.
	Amount int64
	// locking script.
	LockingScript string
	// address (if locking script is usual hashtype.)
	Address string
}

type UtxoData struct {
	// utxo txid
	Txid string
	// utxo vout
	Vout uint32
	// amount
	Amount int64
	// asset
	Asset string
	// output descriptor
	Descriptor string
	// is issuance output
	IsIssuance bool
	// is blind issuance output
	IsBlindIssuance bool
	// is peg-in output
	IsPegin bool
	// peg-in bitcoin tx size (require when IsPegin is true)
	PeginBtcTxSize uint32
	// fedpegscript hex (require when IsPegin is true)
	FedpegScript string
	// scriptsig template hex (require script hash estimate fee)
	ScriptSigTemplate string
	// amount commitment hex
	AmountCommitment string
}

// SigHashType This struct use for the sighashtype utility function.
type SigHashType struct {
	Type         int
	AnyoneCanPay bool
	Rangeproof   bool
}

// NewSigHashType This function return a SigHashType.
func NewSigHashType(sighashType int) *SigHashType {
	value := sighashType & 0x0f
	anyoneCanPay := false
	isRangeproof := false
	if (sighashType & 0x80) != 0 {
		anyoneCanPay = true
	}
	if (sighashType & 0x40) != 0 {
		isRangeproof = true
	}
	return &SigHashType{
		Type:         value,
		AnyoneCanPay: anyoneCanPay,
		Rangeproof:   isRangeproof,
	}
}

// ToHex This function return a sighashtype byte value.
func (obj *SigHashType) GetValue() int {
	value := obj.Type
	if (value & 0x80) != 0 {
		// do nothing
	} else if obj.AnyoneCanPay {
		value |= 0x80
	}
	if (value & 0x40) != 0 {
		// do nothing
	} else if obj.Rangeproof {
		value |= 0x40
	}
	return value
}

/**
 * TransactionData data struct.
 */
type TransactionData struct {
	// txid
	Txid string
	// witness txid
	Wtxid string
	// witness hash
	WitHash string
	// size
	Size uint32
	// virtual size
	Vsize uint32
	// weight
	Weight uint32
	// version
	Version uint32
	// locktime
	LockTime uint32
}

type InputTxIn struct {
	OutPoint OutPoint
	Sequence uint32
}

type InputTxOut struct {
	Amount        int64  // satoshi amount (unblind value)
	LockingScript string // locking script
	Address       string // address or confidential address. (if locking script is usual hashtype.)
}

var SigHashTypeDefault SigHashType = *NewSigHashType(0)
var SigHashTypeAll SigHashType = *NewSigHashType(1)
var SigHashTypeNone SigHashType = *NewSigHashType(2)
var SigHashTypeSingle SigHashType = *NewSigHashType(3)

// -------------------------------------
// implement TransactionUtil
// -------------------------------------

func (u *TransactionUtil) validConfig() error {
	if u.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		if cfdConfig.Network.IsElements() {
			netType := cfdConfig.Network.ToBitcoinType()
			u.Network = &netType
		} else {
			netType := cfdConfig.Network
			u.Network = &netType
		}
	}
	if !u.Network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

func (u *TransactionUtil) Create(version uint32, locktime uint32, txinList *[]InputTxIn, txoutList *[]InputTxOut) (tx *Transaction, err error) {
	if err = u.validConfig(); err != nil {
		return nil, err
	}
	txHandle, err := InitializeTransaction(u.Network.ToCfdValue(), version, locktime)
	if err != nil {
		return nil, err
	}
	defer FreeTransactionHandle(txHandle)

	if err = addTransaction(txHandle, *u.Network, locktime, txinList, txoutList); err != nil {
		return nil, err
	}

	txHex, err := internalFinalizeTransaction(txHandle)
	if err != nil {
		return nil, err
	}
	return &Transaction{Hex: txHex, Network: *u.Network}, nil
}

// -------------------------------------
// implement Transaction
// -------------------------------------

func (t *Transaction) validConfig() error {
	if t.Network == Unknown {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		t.Network = cfdConfig.Network
	}
	if !t.Network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

func (t *Transaction) Add(txinList *[]InputTxIn, txoutList *[]InputTxOut) error {
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

	if err = addTransaction(txHandle, t.Network, data.LockTime, txinList, txoutList); err != nil {
		return err
	}

	txHex, err := internalFinalizeTransaction(txHandle)
	if err != nil {
		return err
	}
	t.Hex = txHex
	return nil
}

// AddPubkeySign ...
func (t *Transaction) AddPubkeySign(outpoint *OutPoint, hashType HashType, pubkey *Pubkey, signature string) error {
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
func (t *Transaction) AddPubkeySignByDescriptor(outpoint *OutPoint, descriptor *Descriptor, signature string) error {
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

// SignWithPrivkey ...
func (t *Transaction) SignWithPrivkey(outpoint *OutPoint, privkey *Privkey, sighashType SigHashType, utxoList *[]UtxoData) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	txinUtxoList := (*[]CfdUtxo)(unsafe.Pointer(utxoList))
	txHex, err := CfdGoAddTxSignWithPrivkeyByUtxoList(t.Network.ToCfdValue(), t.Hex, *txinUtxoList, outpoint.Txid, outpoint.Vout, privkey.Hex, &sighashType, true, nil, nil)
	if err == nil {
		t.Hex = txHex
	}
	return err
}

// VerifySign ...
func (t *Transaction) VerifySign(outpoint *OutPoint, amount int64, txinUtxoList *[]UtxoData) (isVerify bool, reason string, err error) {
	if err := t.validConfig(); err != nil {
		return false, "", err
	}
	utxoList := (*[]CfdUtxo)(unsafe.Pointer(txinUtxoList))
	return CfdGoVerifySign(t.Network.ToCfdValue(), t.Hex, *utxoList, outpoint.Txid, outpoint.Vout)
}

func (t *Transaction) GetTxid() string {
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

// low-layer API ---------------------------------------------------------------

// addConidentialTx ...
func addTransaction(txHandle uintptr, network NetworkType, locktime uint32, txinList *[]InputTxIn, txoutList *[]InputTxOut) error {
	var err error
	if txinList != nil {
		for i := 0; i < len(*txinList); i++ {
			seq := (*txinList)[i].Sequence
			if seq == 0 {
				if locktime == 0 {
					seq = uint32(KCfdSequenceLockTimeFinal)
				} else {
					seq = uint32(KCfdSequenceLockTimeEnableMax)
				}
			}
			err = AddTransactionInput(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
			if err != nil {
				return err
			}
		}
	}

	if txoutList != nil {
		for i := 0; i < len(*txoutList); i++ {
			err = AddTransactionOutput(txHandle, (*txoutList)[i].Amount, (*txoutList)[i].Address, (*txoutList)[i].LockingScript, "")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// InitializeTransaction : initialize createrawtransaction with version & locktime.
// param: networkType      nettype string. (mainnet/testnet/regtest)
// param: version          transaction version.
// param: locktime         transaction locking time.
// return: createTxHandle  handle of createrawtransaction.
// return: err             error
func InitializeTransaction(networkType int, version uint32, locktime uint32) (createTxHandle uintptr, err error) {
	createTxHandle = uintptr(0)
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeTransaction(handle, networkType, versionPtr, locktimePtr, "", &createTxHandle)
	err = convertCfdError(ret, handle)
	return createTxHandle, err
}

// InitializeTransactionByHex : initialize createrawtransaction with hex.
// param: networkType      nettype string. (mainnet/testnet/regtest)
// param: txHex            transaction hex.
// return: createTxHandle  handle of createrawtransaction.
// return: err             error
func InitializeTransactionByHex(networkType int, txHex string) (createTxHandle uintptr, err error) {
	return internalInitializeTransactionByHex(networkType, txHex)
}

// AddTransactionInput : add createrawtransaction input data. (bitcoin, elements)
// param: createTxHandle   handle of createrawtransaction.
// param: txid             txid of utxo.
// param: vout             vout of utxo.
// param: sequence         sequence number.
// return: err             error
func AddTransactionInput(createTxHandle uintptr, txid string, vout uint32, sequence uint32) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdAddTransactionInput(handle, createTxHandle, txid, voutPtr, sequencePtr)
	err = convertCfdError(ret, handle)
	return err
}

// AddTransactionInput : add createrawtransaction output data. (bitcoin, elements)
// param: createTxHandle   handle of createrawtransaction.
// param: amount           satoshi amount.
// param: address          address.
// param: lockingScript    locking script. (ignore address)
// param: asset            target asset. (only elements)
// return: err             error
func AddTransactionOutput(createTxHandle uintptr, amount int64, address string, lockingScript string, asset string) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdAddTransactionOutput(handle, createTxHandle, amountPtr, address, lockingScript, asset)
	err = convertCfdError(ret, handle)
	return err
}

// FinalizeTransaction : finalize createrawtransaction. (bitcoin, elements)
// param: createTxHandle   handle of createrawtransaction.
// return: txHex           transaction hex.
// return: err             error
func FinalizeTransaction(createTxHandle uintptr) (txHex string, err error) {
	return internalFinalizeTransaction(createTxHandle)
}

// FreeTransactionHandle : free createrawtransaction handle.
// param: createTxHandle   handle of createrawtransaction.
func FreeTransactionHandle(createTxHandle uintptr) {
	CfdFreeTransactionHandle(uintptr(0), createTxHandle)
}

func GetBitcoinTransactionData(txHex string, hasWitness bool) (data TransactionData, txinList []TxIn, txoutList []TxOut, err error) {
	data, txinList, txoutList, err = GetTransactionDataAll(txHex, hasWitness, false, int(KCfdNetworkMainnet))
	return
}

func GetTransactionDataAll(txHex string, hasWitness bool, hasAddress bool, networkType int) (data TransactionData, txinList []TxIn, txoutList []TxOut, err error) {
	handle, err := CfdGoInitializeTxDataHandle(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdGoFreeTxDataHandle(handle)

	tempData, err := CfdGoGetTxInfoByHandle(handle)
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

	tempTxins := make([]TxIn, txinCount)
	for i := uint32(0); i < txinCount; i++ {
		txid, vout, sequence, scriptSig, err := CfdGoGetTxInByHandle(handle, i)
		if err != nil {
			return data, txinList, txoutList, err
		}

		tempTxins[i].OutPoint.Txid = txid
		tempTxins[i].OutPoint.Vout = vout
		tempTxins[i].Sequence = sequence
		tempTxins[i].ScriptSig = scriptSig
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
		}
	}

	tempTxouts := make([]TxOut, txoutCount)
	for i := uint32(0); i < txoutCount; i++ {
		satoshiAmount, lockingScript, _, err := CfdGoGetTxOutByHandle(handle, i)
		if err != nil {
			return data, txinList, txoutList, err
		}
		tempTxouts[i].Amount = satoshiAmount
		tempTxouts[i].LockingScript = lockingScript
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
	data.Size = tempData.Size
	data.Vsize = tempData.Vsize
	data.Weight = tempData.Weight
	data.Version = tempData.Version
	data.LockTime = tempData.LockTime
	txinList = tempTxins
	txoutList = tempTxouts
	return data, txinList, txoutList, nil
}

func GetTxOut(txHex string, vout uint32, networkType int) (txout *TxOut, err error) {
	handle, err := CfdGoInitializeTxDataHandle(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdGoFreeTxDataHandle(handle)

	var output TxOut
	satoshiAmount, lockingScript, _, err := CfdGoGetTxOutByHandle(handle, vout)
	if err != nil {
		return nil, err
	}
	output.Amount = satoshiAmount
	output.LockingScript = lockingScript
	addr, tempErr := CfdGoGetAddressFromLockingScript(lockingScript, networkType)
	if tempErr == nil {
		output.Address = addr
	}
	return &output, nil
}

// internalInitializeTransactionByHex This function return a transaction handle.
func internalInitializeTransactionByHex(networkType int, txHex string) (createTxHandle uintptr, err error) {
	createTxHandle = uintptr(0)
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	version := 0
	locktime := 0
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeTransaction(handle, networkType, versionPtr, locktimePtr, txHex, &createTxHandle)
	err = convertCfdError(ret, handle)
	return createTxHandle, err
}

// internalFinalizeTransaction This function return a transacton hex.
func internalFinalizeTransaction(createTxHandle uintptr) (txHex string, err error) {
	txHex = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFinalizeTransaction(handle, createTxHandle, &txHex)
	err = convertCfdError(ret, handle)
	return txHex, err
}

// GetTransactionHex This function return a transacton hex.
func GetTransactionHex(createTxHandle uintptr) (txHex string, err error) {
	return internalFinalizeTransaction(createTxHandle)
}

// SignWithPrivkeyByHandle This function has adding sign with prikey.
func SignWithPrivkeyByHandle(createTxHandle uintptr, txid string, vout uint32, privkey string, sighashType *SigHashType, hasGrindR bool, auxRand, annex *ByteData) error {
	if sighashType == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	auxRandStr := ""
	annexStr := ""
	if auxRand != nil {
		auxRandStr = auxRand.hex
	}
	if annex != nil {
		annexStr = annex.hex
	}
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddSignWithPrivkeyByHandle(handle, createTxHandle, txid, voutPtr, privkey, sighashType.GetValue(), sighashType.AnyoneCanPay, hasGrindR, auxRandStr, annexStr)
	err = convertCfdError(ret, handle)
	return err
}

// SetUtxoListByHandle This function has adding utxo list.
func SetUtxoListByHandle(createTxHandle uintptr, txinUtxoList []CfdUtxo) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	for index := 0; index < len(txinUtxoList); index++ {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinUtxoList[index].Vout)))
		satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txinUtxoList[index].Amount)))
		ret := CfdSetTransactionUtxoData(handle, createTxHandle, txinUtxoList[index].Txid, voutPtr, satoshiAmountPtr, txinUtxoList[index].AmountCommitment, txinUtxoList[index].Descriptor, "", txinUtxoList[index].Asset, txinUtxoList[index].ScriptSigTemplate, false)
		if err = convertCfdError(ret, handle); err != nil {
			return err
		}
	}

	return nil
}

// SplitTxOut This function set the split outputs.
func SplitTxOut(createTxHandle uintptr, index uint32, txouts []CfdTxOut) error {
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
		ret := CfdAddSplitTxOutData(handle, splitTxHandle, amountPtr, txout.Address, txout.LockingScript, "")
		if err = convertCfdError(ret, handle); err != nil {
			return err
		}
	}

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret = CfdSplitTxOut(handle, createTxHandle, splitTxHandle, indexPtr)
	return convertCfdError(ret, handle)
}

// GetTxOutIndexes This function get txout index list.
func GetTxOutIndexes(createTxHandle uintptr, address, directLockingScript string) (indexes []uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return indexes, err
	}
	defer CfdGoFreeHandle(handle)

	outputIndex := uint32(0)
	outputIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&outputIndex)))
	offset := uint32(0)
	offsetPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&offset)))
	ret := CfdGetTxOutIndexWithOffsetByHandle(handle, createTxHandle, offsetPtr, address, directLockingScript, outputIndexPtr)
	if err = convertCfdError(ret, handle); err != nil {
		return indexes, err
	}
	indexes = append(indexes, outputIndex)
	offset = outputIndex + 1

	for {
		offsetPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&offset)))
		ret := CfdGetTxOutIndexWithOffsetByHandle(handle, createTxHandle, offsetPtr, address, directLockingScript, outputIndexPtr)
		if ret == int(KCfdOutOfRangeError) {
			break
		} else if err = convertCfdError(ret, handle); err != nil {
			return indexes, err
		}
		indexes = append(indexes, outputIndex)
		offset = outputIndex + 1
	}
	return indexes, err
}

// UpdateTxInSequence This function set a sequence number.
func UpdateTxInSequence(createTxHandle uintptr, txid string, vout uint32, sequence uint32) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdUpdateTxInSequence(handle, createTxHandle, txid, voutPtr, sequencePtr)
	return convertCfdError(ret, handle)
}

// UpdateWitnessStack This function set a witness stack item.
func UpdateWitnessStack(createTxHandle uintptr, txid string, vout uint32, witnessIndex uint32, data string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	witnessIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&witnessIndex)))
	ret := CfdUpdateWitnessStack(handle, createTxHandle, int(KCfdTxWitnessStackNormal), txid, voutPtr, witnessIndexPtr, data)
	return convertCfdError(ret, handle)
}

// GetSighash This function return a sighash.
func GetSighash(createTxHandle uintptr, txid string, vout uint32, sighashType *SigHashType, pubkey *ByteData, redeemScript *Script, tapLeafHash, annex *ByteData, codeSeparatorPosition *uint32) (sighash string, err error) {
	sighash = ""
	if sighashType == nil {
		err = convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
		return
	}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	pubkeyStr := ""
	scriptStr := ""
	tapLeafHashStr := ""
	annexStr := ""
	codeSeparatorPos := uint32(0xffffffff)
	if pubkey != nil {
		pubkeyStr = pubkey.hex
	}
	if redeemScript != nil {
		scriptStr = redeemScript.hex
	}
	if tapLeafHash != nil {
		tapLeafHashStr = tapLeafHash.hex
	}
	if annex != nil {
		annexStr = annex.hex
	}
	if codeSeparatorPosition != nil {
		codeSeparatorPos = *codeSeparatorPosition
	}

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	codeSeparatorPosPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&codeSeparatorPos)))
	ret := CfdCreateSighashByHandle(handle, createTxHandle, txid, voutPtr, sighashType.GetValue(), sighashType.AnyoneCanPay, pubkeyStr, scriptStr, tapLeafHashStr, codeSeparatorPosPtr, annexStr, &sighash)
	err = convertCfdError(ret, handle)
	return
}

// VerifySign This function return a verify sign results.
func VerifySign(createTxHandle uintptr, txid string, vout uint32) (isVerify bool, reason string, err error) {
	isVerify = false
	reason = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return isVerify, reason, err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdVerifyTxSignByHandle(handle, createTxHandle, txid, voutPtr)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		CfdGetLastErrorMessage(handle, &reason)
	} else {
		err = convertCfdError(ret, handle)
		CfdGetLastErrorMessage(handle, &reason)
	}
	return isVerify, reason, err
}

// AddTaprootSchnorrSign This function add a taproot schnorr sign.
func AddTaprootSchnorrSign(createTxHandle uintptr, txid string, vout uint32, signature *ByteData, annex *ByteData) error {
	if signature == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	annexStr := ""
	if annex != nil {
		annexStr = annex.hex
	}
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddTaprootSignByHandle(handle, createTxHandle, txid, voutPtr, signature.hex, "", "", annexStr)
	return convertCfdError(ret, handle)
}

// AddTapScriptSign This function add a tapscript sign.
func AddTapScriptSign(createTxHandle uintptr, txid string, vout uint32, signDataList []ByteData, tapscript *Script, controlBlock *ByteData, annex *ByteData) error {
	if tapscript == nil || controlBlock == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}

	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	for index := 0; index < len(signDataList); index++ {
		ret := CfdAddTxSignByHandle(handle, createTxHandle, txid, voutPtr, (int)(KCfdTaproot), signDataList[index].hex, false, 0, false, false)
		if err = convertCfdError(ret, handle); err != nil {
			return err
		}
	}

	annexStr := ""
	if annex != nil {
		annexStr = annex.hex
	}
	ret := CfdAddTaprootSignByHandle(handle, createTxHandle, txid, voutPtr, "", tapscript.hex, controlBlock.hex, annexStr)
	err = convertCfdError(ret, handle)
	return err
}
