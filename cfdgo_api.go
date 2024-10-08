package cfdgo

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

/**
 * Convert return code to golang built-in error struct.
 * param: retCode   return code from cfd
 * return: err      built-in error struct.
 */
func ConvertCfdErrorCode(retCode int) (err error) {
	switch retCode {
	case (int)(KCfdSuccess):
		return nil
	case (int)(KCfdUnknownError):
		err = errors.Errorf("CFD Error: Unknown error occuered.: errorCode=[%d]", retCode)
	case (int)(KCfdInternalError):
		err = errors.Errorf("CFD Error: Internal error occered.: errorCode=[%d]", retCode)
	case (int)(KCfdMemoryFullError):
		err = errors.Errorf("CFD Error: Memory is full.: errorCode=[%d]", retCode)
	case (int)(KCfdIllegalArgumentError):
		err = errors.Errorf("CFD Error: Illegal argument passed.: errorCode=[%d]", retCode)
	case (int)(KCfdIllegalStateError):
		err = errors.Errorf("CFD Error: Illegal state api call.: errorCode=[%d]", retCode)
	case (int)(KCfdOutOfRangeError):
		err = errors.Errorf("CFD Error: Out of range access occered.: errorCode=[%d]", retCode)
	case (int)(KCfdInvalidSettingError):
		err = errors.Errorf("CFD Error: Invalid setting api call.: errorCode=[%d]", retCode)
	case (int)(KCfdConnectionError):
		err = errors.Errorf("CFD Error: Connection error occered.: errorCode=[%d]", retCode)
	case (int)(KCfdDiskAccessError):
		err = errors.Errorf("CFD Error: Disk access error occered.: errorCode=[%d]", retCode)
	case (int)(KCfdNotFoundError):
		err = errors.Errorf("CFD Error: NotFound error occered.: errorCode=[%d]", retCode)
	}
	return
}

/**
 * Convert handle and error code to Golang built-in error.
 * detail: if handle is nil, return fixed message by the error code.
 * param: retCode   cfd return code.
 * param: handle    cfd handle.
 * return: err      built-in error struct.
 */
func convertCfdError(retCode int, handle uintptr) (err error) {
	if retCode == (int)(KCfdSuccess) {
		return
	}

	var errorMsg string
	if handle == uintptr(0) {
		err = ConvertCfdErrorCode(retCode)
	} else if ret := CfdGetLastErrorMessage(handle, &errorMsg); ret != (int)(KCfdSuccess) {
		err = ConvertCfdErrorCode(retCode)
	} else {
		err = errors.Errorf("CFD Error: message=[%s], code=[%d]", errorMsg, retCode)
	}
	return
}

/**
 * Get supported function.
 * return: funcFlag    function flag.
 * return: err         error struct
 */
func CfdGoGetSupportedFunction() (funcFlag uint64, err error) {
	funcFlagValue := SwigcptrUint64_t(uintptr(unsafe.Pointer(&funcFlag)))
	ret := CfdGetSupportedFunction(funcFlagValue)
	err = convertCfdError(ret, uintptr(0))
	return funcFlag, err
}

/**
 * Create cfd handle.
 * return: handle      cfd handle. release: CfdGoFreeHandle
 * return: err         error struct
 */
func CfdGoCreateHandle() (handle uintptr, err error) {
	ret := CfdCreateSimpleHandle(&handle)
	err = convertCfdError(ret, handle)
	return handle, err
}

/**
 * Free cfd handle.
 * param: handle       cfd handle
 * return: err         error struct
 */
func CfdGoFreeHandle(handle uintptr) (err error) {
	ret := CfdFreeHandle(handle)
	err = convertCfdError(ret, uintptr(0))
	return
}

/**
 * Create Address.
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * param: pubkey        pubkey (pubkey hash only)
 * param: redeemScript  redeem script (script hash only)
 * param: networkType   network type
 * return: address                  address string
 * return: lockingScript            locking script
 * return: p2shSegwitLockingScript  p2sh-segwit witness program
 * return: err                      error
 */
func CfdGoCreateAddress(hashType int, pubkey string, redeemScript string, networkType int) (address string, lockingScript string, p2shSegwitLockingScript string, err error) {

	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateAddress(handle, hashType, pubkey, redeemScript, networkType, &address, &lockingScript, &p2shSegwitLockingScript)
	err = convertCfdError(ret, handle)
	return address, lockingScript, p2shSegwitLockingScript, err
}

/**
 * Create multisig script and address.
 * param: networkType   network type
 * param: hashType      hash type (p2sh, p2wsh, etc...)
 * param: pubkeys       pubkey list (max 15 key)
 * param: requireNum    pubkey require signature
 * return: address        address string
 * return: redeemScript   redeem script
 * return: witnessScript  witness script
 * return: err            error
 */
func CfdGoCreateMultisigScript(networkType int, hashType int, pubkeys []string, requireNum uint32) (address string, redeemScript string, witnessScript string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var multisigHandle uintptr
	ret := CfdInitializeMultisigScript(handle, networkType, hashType, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeMultisigScriptHandle(handle, multisigHandle)

	for i := 0; i < len(pubkeys); i++ {
		ret = CfdAddMultisigScriptData(handle, multisigHandle, pubkeys[i])
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		reqNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&requireNum)))
		ret = CfdFinalizeMultisigScript(handle, multisigHandle, reqNumPtr, &address, &redeemScript, &witnessScript)
	}

	if ret == (int)(KCfdSuccess) {
		return address, redeemScript, witnessScript, err
	} else {
		err = convertCfdError(ret, handle)
		return "", "", "", err
	}
}

/**
 * Descriptor data struct.
 */
type CfdDescriptorData struct {
	// depth (0 - )
	Depth uint32
	// script type. (CfdDescriptorScriptType)
	ScriptType int
	// locking script.
	LockingScript string
	// address string. (for ScriptType not KCfdDescriptorScriptRaw)
	Address string
	// hash type. (CfdHashType)
	HashType int
	// redeem script. (for ScriptType KCfdDescriptorScriptSh or KCfdDescriptorScriptWsh)
	RedeemScript string
	// key type. (see CfdDescriptorKeyData.KeyType)
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
	// has multisig
	IsMultisig bool
	// number of multisig require signatures
	ReqSigNum uint32
	// Taproot ScriptTree string
	TreeString string
}

/**
 * Descriptor key data struct.
 */
type CfdDescriptorKeyData struct {
	// key type. (CfdDescriptorKeyType)
	// - KCfdDescriptorKeyNull
	// - KCfdDescriptorKeyPublic
	// - KCfdDescriptorKeyBip32
	// - KCfdDescriptorKeyBip32Priv
	// - KCfdDescriptorKeySchnorr
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
}

/**
 * Parse Output Descriptor.
 * param: descriptor           output descriptor
 * param: networkType          network type
 * param: bip32DerivationPath  derive path
 * return: data                descriptor data
 * return: descriptorDataList  descriptor data struct list
 * return: multisigList        multisig key struct list
 * return: err                 error
 */
func CfdGoParseDescriptorData(descriptor string, networkType int, bip32DerivationPath string) (data CfdDescriptorData, descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var descriptorHandle uintptr
	var maxIndex uint32
	maxIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxIndex)))
	ret := CfdParseDescriptor(handle, descriptor, networkType, bip32DerivationPath, &descriptorHandle, maxIndexPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeDescriptorHandle(handle, descriptorHandle)

	var maxMultisigKeyNum uint32
	lastMultisigFlag := false
	keyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxMultisigKeyNum)))
	{
		reqSigNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(data.ReqSigNum))))
		ret = CfdGetDescriptorRootData(handle, descriptorHandle,
			&data.ScriptType, &data.LockingScript,
			&data.Address, &data.HashType, &data.RedeemScript,
			&data.KeyType, &data.Pubkey, &data.ExtPubkey, &data.ExtPrivkey,
			&data.SchnorrPubkey, &data.TreeString,
			&data.IsMultisig, keyNumPtr, reqSigNumPtr)
	}

	if ret == (int)(KCfdSuccess) {
		descriptorDataList = make([]CfdDescriptorData, maxIndex+1)
		for i := uint32(0); i <= maxIndex; i++ {
			var tempData CfdDescriptorData
			var maxNum uint32
			maxNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxNum)))
			depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(tempData.Depth))))
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			reqSigNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(tempData.ReqSigNum))))
			ret = CfdGetDescriptorData(handle, descriptorHandle, index, maxNumPtr,
				depthPtr, &tempData.ScriptType, &tempData.LockingScript,
				&tempData.Address, &tempData.HashType, &tempData.RedeemScript,
				&tempData.KeyType, &tempData.Pubkey, &tempData.ExtPubkey, &tempData.ExtPrivkey,
				&tempData.IsMultisig, keyNumPtr, reqSigNumPtr)
			if ret != (int)(KCfdSuccess) {
				break
			}
			if tempData.KeyType == (int)(KCfdDescriptorKeySchnorr) {
				tempData.SchnorrPubkey = tempData.Pubkey
				tempData.Pubkey = ""
			}
			descriptorDataList[i] = tempData
			lastMultisigFlag = tempData.IsMultisig
		}
	}

	if lastMultisigFlag && (ret == (int)(KCfdSuccess)) {
		multisigList = make([]CfdDescriptorKeyData, maxMultisigKeyNum)
		for i := uint32(0); i < maxMultisigKeyNum; i++ {
			var keyData CfdDescriptorKeyData
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			ret = CfdGetDescriptorMultisigKey(handle, descriptorHandle,
				index, &keyData.KeyType, &keyData.Pubkey,
				&keyData.ExtPubkey, &keyData.ExtPrivkey)
			if ret != (int)(KCfdSuccess) {
				break
			}
			multisigList[i] = keyData
		}
	}

	if ret == (int)(KCfdSuccess) {
		return data, descriptorDataList, multisigList, err
	} else {
		err = convertCfdError(ret, handle)
		return data, []CfdDescriptorData{}, []CfdDescriptorKeyData{}, err
	}
}

/**
 * Parse Output Descriptor.
 * param: descriptor           output descriptor
 * param: networkType          network type
 * param: bip32DerivationPath  derive path
 * return: descriptorDataList  descriptor data struct list
 * return: multisigList        multisig key struct list
 * return: err                 error
 */
func CfdGoParseDescriptor(descriptor string, networkType int, bip32DerivationPath string) (descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, err error) {
	_, descriptorDataList, multisigList, err = CfdGoParseDescriptorData(descriptor, networkType, bip32DerivationPath)
	return descriptorDataList, multisigList, err
}

/**
 * Get outputDescriptor's checksum.
 * param: networkType    network type
 * param: descriptor     descriptor.
 * return: descriptorAddedChecksum   descriptor added checksum.
 * return: err                       error
 */
func CfdGoGetDescriptorChecksum(networkType int, descriptor string) (descriptorAddedChecksum string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetDescriptorChecksum(handle, networkType, descriptor, &descriptorAddedChecksum)
	err = convertCfdError(ret, handle)
	return descriptorAddedChecksum, err
}

/**
 * Get multisig pubkeys address.
 * param: redeemScript  multisig script
 * param: networkType   network type
 * param: hashType      hash type (p2sh, p2wsh, etc...)
 * return: addressList  address list
 * return: pubkeyList   pubkey list
 * return: err          error
 */
func CfdGoGetAddressesFromMultisig(redeemScript string, networkType int, hashType int) (addressList []string, pubkeyList []string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var multisigHandle uintptr
	var maxKeyNum uint32
	maxKeyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxKeyNum)))

	ret := CfdGetAddressesFromMultisig(handle, redeemScript, networkType,
		hashType, &multisigHandle, maxKeyNumPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeAddressesMultisigHandle(handle, multisigHandle)

	addressList = make([]string, maxKeyNum)
	pubkeyList = make([]string, maxKeyNum)
	for i := uint32(0); i < maxKeyNum; i++ {
		var pubkey string
		var address string
		index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		ret = CfdGetAddressFromMultisigKey(handle, multisigHandle,
			index, &address, &pubkey)
		if ret != (int)(KCfdSuccess) {
			break
		}
		addressList[i] = address
		pubkeyList[i] = pubkey
	}

	if ret == (int)(KCfdSuccess) {
		return addressList, pubkeyList, err
	} else {
		err = convertCfdError(ret, handle)
		return []string{}, []string{}, err
	}
}

/**
 * Get address from locking script.
 * param: lockingScript  locking script
 * param: networkType    network type
 * param: hashType       hash type (p2sh, p2wsh, etc...)
 * return: address       address
 * return: err           error
 */
func CfdGoGetAddressFromLockingScript(lockingScript string, networkType int) (address string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetAddressFromLockingScript(handle, lockingScript, networkType, &address)
	err = convertCfdError(ret, handle)
	return address, err
}

/**
 * Address information struct.
 */
type CfdAddressInfo struct {
	// address
	Address string
	// network type
	NetworkType int
	// hash type
	HashType int
	// witness version (unuse: -1)
	WitnessVersion int
	// locking script
	LockingScript string
	// hash
	Hash string
}

/**
 * Get address information.
 * param: address        address string
 * return: data          address data (CfdAddressInfo)
 * return: err           error
 */
func CfdGoGetAddressInfo(address string) (data CfdAddressInfo, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetAddressInfo(handle, address, &data.NetworkType, &data.HashType, &data.WitnessVersion, &data.LockingScript, &data.Hash)
	err = convertCfdError(ret, handle)
	if err == nil {
		data.Address = address
		if data.WitnessVersion > 2147483647 {
			data.WitnessVersion = (int)(KCfdWitnessVersionNone)
		}
	}
	return data, err
}

/**
 * UTXO struct.
 */
type CfdUtxo struct {
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
	// claim script hex (require when IsPegin is true)
	ClaimScript string
	// peg-in bitcoin tx size (require when IsPegin is true)
	PeginBtcTxSize uint32
	// peg-in bitcoin txoutproof size (require when IsPegin is true)
	PeginTxOutProofSize uint32
	// scriptsig template hex (require script hash estimate fee)
	ScriptSigTemplate string
	// amount commitment hex
	AmountCommitment string
	// asset commitment hex
	AssetCommitment string
	// amount blinder hex
	AmountBlinder string
	// asset blinder hex
	AssetBlinder string
	// genesis block hash
	GenesisBlockHash string
}

/**
 * Selection target amount struct.
 */
type CfdTargetAmount struct {
	// Amount more than the specified amount is set in txout. default is 0 (disable).
	Amount int64
	// asset
	Asset string
}

/**
 * CoinSelection option data struct.
 */
type CfdCoinSelectOption struct {
	// fee asset
	FeeAsset string
	// tx-fee amount
	TxFeeAmount int64
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value. knapsack logic's threshold. Recommended value is 1.
	KnapsackMinChange int64
	// blind exponent. default is 0.
	Exponent int64
	// blind minimum bits. default is -1 (cfd-go auto).
	MinimumBits int64
}

/**
 * Create CfdCoinSelectOption struct set default value.
 * return: option        CoinSelection option
 */
func NewCfdCoinSelectionOption() CfdCoinSelectOption {
	option := CfdCoinSelectOption{}
	option.EffectiveFeeRate = float64(20.0)
	option.LongTermFeeRate = float64(-1.0)
	option.DustFeeRate = float64(-1.0)
	option.KnapsackMinChange = int64(-1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	return option
}

/**
 * Select coins.
 * param: utxos          utxo array
 * param: targetAmounts  target amount array
 * param: option         option for coinSelection
 * return: selectUtxos   select coins
 * return: totalAmounts  select amount by asset
 * return: utxoFee       fee by utxo
 * return: err           error
 */
func CfdGoCoinSelection(utxos []CfdUtxo, targetAmounts []CfdTargetAmount, option CfdCoinSelectOption) (selectUtxos []CfdUtxo, totalAmounts []CfdTargetAmount, utxoFee int64, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var coinSelectHandle uintptr
	utxoCount := (uint32)(len(utxos))
	amountCount := (uint32)(len(targetAmounts))
	utxoCountBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxoCount)))
	amountCountBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&amountCount)))
	txFeeAmountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.TxFeeAmount)))
	knapsackMinChangeBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.KnapsackMinChange)))
	ret := CfdInitializeCoinSelection(handle, utxoCountBuf,
		amountCountBuf, option.FeeAsset, txFeeAmountBuf,
		option.EffectiveFeeRate, option.LongTermFeeRate, option.DustFeeRate,
		knapsackMinChangeBuf, &coinSelectHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeCoinSelectionHandle(handle, coinSelectHandle)

	for i := int32(0); i < (int32)(utxoCount); i++ {
		indexBuf := SwigcptrInt32_t(uintptr(unsafe.Pointer(&i)))
		voutBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxos[i].Vout)))
		amountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxos[i].Amount)))
		ret = CfdAddCoinSelectionUtxoTemplate(handle, coinSelectHandle, indexBuf, utxos[i].Txid, voutBuf, amountBuf, utxos[i].Asset, utxos[i].Descriptor, utxos[i].ScriptSigTemplate)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	for i := uint32(0); i < amountCount; i++ {
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		amountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&targetAmounts[i].Amount)))
		ret = CfdAddCoinSelectionAmount(handle, coinSelectHandle, indexBuf, amountBuf, targetAmounts[i].Asset)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.Exponent)))
	ret = CfdSetOptionCoinSelection(handle, coinSelectHandle, int(KCfdCoinSelectionExponent), exponentPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	minimumBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.MinimumBits)))
	ret = CfdSetOptionCoinSelection(handle, coinSelectHandle, int(KCfdCoinSelectionMinimumBits), minimumBitsPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	utxoFeeBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxoFee)))
	ret = CfdFinalizeCoinSelection(handle, coinSelectHandle, utxoFeeBuf)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	selectUtxoCount := 0
	tempUtxos := make([]CfdUtxo, utxoCount)
	for i := uint32(0); i < utxoCount; i++ {
		utxoIndex := int32(0)
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		utxoIndexBuf := SwigcptrInt32_t(uintptr(unsafe.Pointer(&utxoIndex)))
		ret = CfdGetSelectedCoinIndex(handle, coinSelectHandle, indexBuf, utxoIndexBuf)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
		if utxoIndex < 0 {
			break
		}
		tempUtxos[i] = utxos[utxoIndex]
		selectUtxoCount += 1
	}
	if selectUtxoCount > 0 {
		selectUtxos = make([]CfdUtxo, selectUtxoCount)
		for i := 0; i < selectUtxoCount; i++ {
			selectUtxos[i] = tempUtxos[i]
		}
	}

	totalAmounts = make([]CfdTargetAmount, amountCount)
	for i := uint32(0); i < amountCount; i++ {
		amount := int64(0)
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		amountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
		ret = CfdGetSelectedCoinAssetAmount(handle, coinSelectHandle, indexBuf, amountBuf)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
		totalAmounts[i] = targetAmounts[i]
		totalAmounts[i].Amount = amount
	}
	return
}

/**
 * EstimateFee Input data struct.
 * (deprecated) Because it is already integrated with CfdUtxo.
 */
type CfdEstimateFeeInput struct {
	// utxo data
	Utxo CfdUtxo
	// is issuance input
	IsIssuance bool
	// is blind issuance input
	IsBlindIssuance bool
	// is peg-in input
	IsPegin bool
	// claimscript hex (require when IsPegin is true)
	ClaimScript string
	// peg-in bitcoin tx size (require when IsPegin is true)
	PeginBtcTxSize uint32
	// peg-in bitcoin txoutproof size (require when IsPegin is true)
	PeginTxOutProofSize uint32
}

/**
 * EstimateFee option data struct.
 */
type CfdFeeEstimateOption struct {
	// effective feerate
	EffectiveFeeRate float64
	// use elements chain
	UseElements bool
	// fee asset
	FeeAsset string
	// Require blinding or not
	RequireBlind bool
	// blinding exponent value
	Exponent int64
	// blinding minimum bits value
	MinimumBits int64
}

/**
 * Create CfdFeeEstimateOption struct set default value.
 * return: option        EstimateFeeOption
 */
func NewCfdEstimateFeeOption() CfdFeeEstimateOption {
	option := CfdFeeEstimateOption{}
	option.EffectiveFeeRate = float64(20.0)
	option.UseElements = true
	option.FeeAsset = ""
	option.RequireBlind = true
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	return option
}

/**
 * Estimate fee amount.
 * param: txHex         transaction hex
 * param: inputs        inputs to set in the transaction
 * param: option        options for fee estimation
 * return: totalFee     total fee value when all utxos set to input.
 *     (totalFee = txoutFee + utxoFee)
 * return: txoutFee     base transaction fee value.
 * return: utxoFee      fee value all of input set utxo.
 */
func CfdGoEstimateFee(txHex string, inputs []CfdEstimateFeeInput, option CfdFeeEstimateOption) (totalFee, txoutFee, utxoFee int64, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var estimateFeeHandle uintptr
	if ret := CfdInitializeEstimateFee(
		handle,
		&estimateFeeHandle,
		option.UseElements,
	); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeEstimateFeeHandle(handle, estimateFeeHandle)

	for _, input := range inputs {
		vout := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.Utxo.Vout)))
		peginBtcTxSize := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.PeginBtcTxSize)))
		txOutProofSize := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.PeginTxOutProofSize)))
		if ret := CfdAddTxInputForEstimateFee(
			handle,
			estimateFeeHandle,
			input.Utxo.Txid,
			vout,
			input.Utxo.Descriptor,
			input.Utxo.Asset,
			input.IsIssuance,
			input.IsBlindIssuance,
			input.IsPegin,
			input.ClaimScript,
			peginBtcTxSize,
			txOutProofSize,
			input.Utxo.ScriptSigTemplate,
		); ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.Exponent)))
	ret := CfdSetOptionEstimateFee(handle, estimateFeeHandle, int(KCfdEstimateFeeExponent), exponentPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	minimumBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.MinimumBits)))
	ret = CfdSetOptionEstimateFee(handle, estimateFeeHandle, int(KCfdEstimateFeeMinimumBits), minimumBitsPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	var txFeeWork, inputFeeWork int64
	txFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txFeeWork)))
	inputFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&inputFeeWork)))
	if ret := CfdFinalizeEstimateFee(
		handle,
		estimateFeeHandle,
		txHex,
		option.FeeAsset,
		txFeeWorkPtr,
		inputFeeWorkPtr,
		option.RequireBlind,
		option.EffectiveFeeRate,
	); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	totalFee = txFeeWork + inputFeeWork
	txoutFee = txFeeWork
	utxoFee = inputFeeWork
	return
}

/**
 * Estimate fee amount.
 * param: txHex         transaction hex
 * param: inputs        inputs to set in the transaction
 * param: option        options for fee estimation
 * return: totalFee     total fee value when all utxos set to input.
 *     (totalFee = txoutFee + utxoFee)
 * return: txoutFee     base transaction fee value.
 * return: utxoFee      fee value all of input set utxo.
 */
func CfdGoEstimateFeeUsingUtxo(txHex string, inputs []CfdUtxo, option CfdFeeEstimateOption) (totalFee, txoutFee, utxoFee int64, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var estimateFeeHandle uintptr
	if ret := CfdInitializeEstimateFee(
		handle,
		&estimateFeeHandle,
		option.UseElements,
	); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeEstimateFeeHandle(handle, estimateFeeHandle)

	for _, input := range inputs {
		vout := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.Vout)))
		peginBtcTxSize := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.PeginBtcTxSize)))
		txoutproofSize := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.PeginTxOutProofSize)))
		if ret := CfdAddTxInputForEstimateFee(
			handle,
			estimateFeeHandle,
			input.Txid,
			vout,
			input.Descriptor,
			input.Asset,
			input.IsIssuance,
			input.IsBlindIssuance,
			input.IsPegin,
			input.ClaimScript,
			peginBtcTxSize,
			txoutproofSize,
			input.ScriptSigTemplate,
		); ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.Exponent)))
	ret := CfdSetOptionEstimateFee(handle, estimateFeeHandle, int(KCfdEstimateFeeExponent), exponentPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	minimumBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.MinimumBits)))
	ret = CfdSetOptionEstimateFee(handle, estimateFeeHandle, int(KCfdEstimateFeeMinimumBits), minimumBitsPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	var txFeeWork, inputFeeWork int64
	txFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txFeeWork)))
	inputFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&inputFeeWork)))
	if ret := CfdFinalizeEstimateFee(
		handle,
		estimateFeeHandle,
		txHex,
		option.FeeAsset,
		txFeeWorkPtr,
		inputFeeWorkPtr,
		option.RequireBlind,
		option.EffectiveFeeRate,
	); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	totalFee = txFeeWork + inputFeeWork
	txoutFee = txFeeWork
	utxoFee = inputFeeWork
	return
}

/**
 * Get initialized confidential transaction.
 * param: version       transaction version
 * param: locktime      locktime
 * return: txHex        transaction hex
 * return: err          error
 */
func CfdGoInitializeConfidentialTx(version uint32, locktime uint32) (txHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeConfidentialTx(handle, versionPtr, locktimePtr, &txHex)
	err = convertCfdError(ret, handle)
	return txHex, err
}

/**
 * Add txin to confidential transaction.
 * param: txHex         transaction hex
 * param: txid          txid
 * param: vout          vout
 * param: sequence      sequence
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoAddConfidentialTxIn(txHex string, txid string, vout uint32, sequence uint32) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdAddConfidentialTxIn(handle, txHex, txid, voutPtr, sequencePtr, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add txout to confidential transaction.
 * param: txHex               transaction hex
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * param: valueCommitment     amount by commitment bytes.
 * param: address             destination address
 * param: directLockingScript  locking script for direct insert.
 * param: nonce               confidential nonce
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoAddConfidentialTxOut(txHex string, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxOut(handle, txHex, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Update txout of confidential transaction.
 * param: txHex               transaction hex
 * param: index               txout index
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * param: valueCommitment     amount by commitment bytes.
 * param: address             destination address
 * param: directLockingScript  lockingScript for direct insert.
 * param: nonce               confidential nonce
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoUpdateConfidentialTxOut(txHex string, index uint32, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUpdateConfidentialTxOut(handle, txHex, indexPtr, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add output for destroying the specified amount of the specified asset.
 * This function is deprecated.
 * param: txHex               transaction hex
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoAddDestoryConfidentialTxOut(txHex string, asset string, satoshiAmount int64) (outputTxHex string, err error) {
	outputTxHex, err = CfdGoAddDestroyConfidentialTxOut(txHex, asset, satoshiAmount)
	return outputTxHex, err
}

/**
 * Add output for destroying the specified amount of the specified asset.
 * param: txHex               transaction hex
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoAddDestroyConfidentialTxOut(txHex string, asset string, satoshiAmount int64) (outputTxHex string, err error) {
	cfdErrHandle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(cfdErrHandle)

	burnScript, err := CfdGoConvertScriptAsmToHex("OP_RETURN") // byte of OP_RETURN
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxOut(cfdErrHandle, txHex, asset, satoshiPtr, "", "", burnScript, "", &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
	return outputTxHex, err
}

/**
 * TxData data struct.
 */
type CfdTxData struct {
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

/**
 * Get confidential transaction data.
 * param: txHex         transaction hex
 * return: data         transaction data
 * return: err          error
 */
func CfdGoGetConfidentialTxData(txHex string) (data CfdTxData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetConfidentialTxInfo(handle, txHex, &data.Txid, &data.Wtxid, &data.WitHash, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, handle)
	return data, err
}

/**
 * Get txin on confidential transaction.
 * param: txHex         transaction hex
 * param: index         txin index
 * return: txid         txid
 * return: vout         vout
 * return: sequence     sequence
 * return: scriptSig    unlockingScript
 * return: err          error
 */
func CfdGoGetConfidentialTxIn(txHex string, index uint32) (txid string, vout uint32, sequence uint32, scriptSig string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetConfidentialTxIn(handle, txHex, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	err = convertCfdError(ret, handle)
	return txid, vout, sequence, scriptSig, err
}

/**
 * Get witness stack on confidential transaction input.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * param: stackIndex    witness stack index
 * return: stackData    witness stack data
 * return: err          error
 */
func CfdGoGetConfidentialTxInWitness(txHex string, txinIndex uint32, stackIndex uint32) (stackData string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetConfidentialTxInWitness(handle, txHex, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, handle)
	return stackData, err
}

/**
 * Get pegin witness stack on confidential transaction input.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * param: stackIndex    witness stack index
 * return: stackData    witness stack data
 * return: err          error
 */
func CfdGoGetConfidentialTxInPeginWitness(txHex string, txinIndex uint32, stackIndex uint32) (stackData string, err error) {
	cfdErrHandle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(cfdErrHandle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetConfidentialTxInPeginWitness(cfdErrHandle, txHex, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, cfdErrHandle)
	return stackData, err
}

/**
 * Get txin issuance on confidential transaction.
 * param: txHex             transaction hex
 * param: index             txin index
 * return: entropy          blinding asset entropy
 * return: nonce            blinding nonce
 * return: assetAmount      asset amount value
 * return: assetValue       asset commitment value
 * return: tokenAmount      token amount value
 * return: tokenValue       token commitment value
 * return: assetRangeproof  asset rangeproof
 * return: tokenRangeproof  token rangeproof
 * return: err              error
 */
func CfdGoGetTxInIssuanceInfo(txHex string, index uint32) (entropy string, nonce string, assetAmount int64, assetValue string, tokenAmount int64, tokenValue string, assetRangeproof string, tokenRangeproof string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdGetTxInIssuanceInfo(handle, txHex, indexPtr, &entropy, &nonce, assetAmountPtr, &assetValue, tokenAmountPtr, &tokenValue, &assetRangeproof, &tokenRangeproof)
	err = convertCfdError(ret, handle)
	return entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err
}

/**
 * Get txout on confidential transaction.
 * param: txHex         transaction hex
 * param: index         txin index
 * return: asset            asset
 * return: satoshiAmount    amount by satoshi
 * return: valueCommitment  amount by commitment bytes.
 * return: nonce            confidential nonce
 * return: lockingScript    locking script
 * return: surjectionProof  asset surjection proof.
 * return: rangeproof       amount rangeproof.
 * return: err              error
 */
func CfdGoGetConfidentialTxOut(txHex string, index uint32) (asset string, satoshiAmount int64, valueCommitment string, nonce string, lockingScript string, surjectionProof string, rangeproof string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOut(handle, txHex, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript, &surjectionProof, &rangeproof)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err
}

/**
 * Get txin count on confidential transaction.
 * param: txHex         transaction hex
 * return: count        txin count
 * return: err          error
 */
func CfdGoGetConfidentialTxInCount(txHex string) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInCount(handle, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get witness stack count on confidential transaction input.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * return: count        witness stack count
 * return: err          error
 */
func CfdGoGetConfidentialTxInWitnessCount(txHex string, txinIndex uint32) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInWitnessCount(handle, txHex, txinIndexPtr, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get witness stack count on confidential transaction input.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * return: count        witness stack count
 * return: err          error
 */
func CfdGoGetConfidentialTxInPeginWitnessCount(txHex string, txinIndex uint32) (count uint32, err error) {
	cfdErrHandle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(cfdErrHandle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInPeginWitnessCount(cfdErrHandle, txHex, txinIndexPtr, countPtr)
	err = convertCfdError(ret, cfdErrHandle)
	return count, err
}

/**
 * Get txout count on confidential transaction.
 * param: txHex         transaction hex
 * return: count        txout count
 * return: err          error
 */
func CfdGoGetConfidentialTxOutCount(txHex string) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxOutCount(handle, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get txin index on confidential transaction.
 * param: txHex    transaction hex
 * param: txid     transaction id
 * param: vout     transaction vout
 * return: index   txin index
 * return: err     error
 */
func CfdGoGetConfidentialTxInIndex(txHex string, txid string, vout uint32) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetConfidentialTxInIndex(handle, txHex, txid, voutPtr, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

/**
 * Get txout index on confidential transaction.
 * param: txHex                transaction hex
 * param: address              address string
 * param: directLockingScript  lockingScript (if address is empty)
 * return: index               txout index
 * return: err                 error
 */
func CfdGoGetConfidentialTxOutIndex(txHex string, address string, directLockingScript string) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetConfidentialTxOutIndex(handle, txHex, address, directLockingScript, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

/**
 * Set reissuance asset to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: assetSatoshiAmount   generate asset amount
 * param: blindingNonce        blinding nonce
 * param: entropy              entropy
 * param: address              destination address
 * param: directLockingScript  txout locking script on direct.
 * return: asset               generate asset
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoSetRawReissueAsset(txHex string, txid string, vout uint32, assetSatoshiAmount int64, blindingNonce string, entropy string, address string, directLockingScript string) (asset string, outputTxHex string, err error) {
	outputTxHex = ""
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkLiquidv1), txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	asset, err = SetReissueAsset(txHandle, txid, vout, assetSatoshiAmount, blindingNonce, entropy, address, directLockingScript)
	if err != nil {
		return "", "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", "", err
	}
	return asset, outputTxHex, err
}

/**
 * Get issuance blinding key.
 * param: masterBlindingKey    master blinding key
 * param: txid                 utxo txid
 * param: vout                 utxo vout
 * return: blindingKey         issuance blinding key
 * return: err                 error
 */
func CfdGoGetIssuanceBlindingKey(masterBlindingKey string, txid string, vout uint32) (blindingKey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdGetIssuanceBlindingKey(handle, masterBlindingKey, txid, voutPtr, &blindingKey)
	err = convertCfdError(ret, handle)
	return blindingKey, err
}

/**
 * Get default blinding key by locking script.
 * param: masterBlindingKey    master blinding key
 * param: lockingScript        locking script
 * return: blindingKey         blinding key
 * return: err                 error
 */
func CfdGoGetDefaultBlindingKey(masterBlindingKey string, lockingScript string) (blindingKey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetDefaultBlindingKey(handle, masterBlindingKey, lockingScript, &blindingKey)
	err = convertCfdError(ret, handle)
	return blindingKey, err
}

/**
 * Get default blinding key by address.
 * param: masterBlindingKey    master blinding key
 * param: address              address
 * return: blindingKey         blinding key
 * return: err                 error
 */
func CfdGoGetDefaultBlindingKeyByAddress(masterBlindingKey string, address string) (blindingKey string, err error) {
	info, err := CfdGoGetAddressInfo(address)
	if err != nil {
		return "", err
	}

	blindingKey, err = CfdGoGetDefaultBlindingKey(masterBlindingKey, info.LockingScript)
	if err != nil {
		return "", err
	}
	return blindingKey, nil
}

/**
 * Get blind transaction handle.
 * return: blindHandle         blindTx handle. release: CfdGoFreeBlindHandle
 * return: err                 error
 */
func CfdGoInitializeBlindTx() (blindHandle uintptr, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdInitializeBlindTx(handle, &blindHandle)
	err = convertCfdError(ret, handle)
	return blindHandle, err
}

/**
 * Add blind transaction txin data.
 * param: blindHandle          blindTx handle
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: asset                utxo asset
 * param: assetBlindFactor     utxo asset blind factor
 * param: valueBlindFactor     utxo amount blind factor
 * param: satoshiAmount        utxo amount
 * param: assetKey             issuance asset blinding key
 * param: tokenKey             issuance token blinding key
 * return: err                 error
 */
func CfdGoAddBlindTxInData(blindHandle uintptr, txid string, vout uint32, asset string, assetBlindFactor string, valueBlindFactor string, satoshiAmount int64, assetKey string, tokenKey string) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddBlindTxInData(handle, blindHandle, txid, voutPtr, asset, assetBlindFactor, valueBlindFactor, satoshiPtr, assetKey, tokenKey)
	err = convertCfdError(ret, handle)
	return err
}

/**
 * Add blind transaction txout data.
 * param: blindHandle          blindTx handle
 * param: index                txout index
 * param: confidentialKey      confidential key
 * return: err                 error
 */
func CfdGoAddBlindTxOutData(blindHandle uintptr, index uint32, confidentialKey string) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdAddBlindTxOutData(handle, blindHandle, indexPtr, confidentialKey)
	err = convertCfdError(ret, handle)
	return err
}

/**
 * BlindRawTransaction option data struct.
 */
type CfdBlindTxOption struct {
	// blind minimum range value
	MinimumRangeValue int64
	// blind exponent
	Exponent int64
	// blind minimum bits
	MinimumBits int64
}

/** NewCfdBlindTxOption
 * Create CfdBlindTxOption struct set default value.
 * return: option       FundRawTx option
 */
func NewCfdBlindTxOption() CfdBlindTxOption {
	option := CfdBlindTxOption{}
	option.MinimumRangeValue = int64(1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	return option
}

// CfdGoSetBlindTxOption is set blinding optional data.
func CfdGoSetBlindTxOption(blindHandle uintptr, option CfdBlindTxOption) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	minRangeValPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.MinimumRangeValue)))
	ret := CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionMinimumRangeValue), minRangeValPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return err
	}

	exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.Exponent)))
	ret = CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionExponent), exponentPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return err
	}

	minBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.MinimumBits)))
	ret = CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionMinimumBits), minBitsPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return err
	}
	return nil
}

/**
 * Generate blind transaction.
 * param: blindHandle          blindTx handle
 * param: txHex                transaction hex
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoFinalizeBlindTx(blindHandle uintptr, txHex string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFinalizeBlindTx(handle, blindHandle, txHex, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * BlindRawTransaction option data struct.
 */
type BlindData struct {
	// array index
	Vout uint32
	// asset
	Asset string
	// satoshi amount
	Amount int64
	// asset blind factor
	AssetBlindFactor string
	// value blind factor
	ValueBlindFactor string
	// issuance txid
	IssuanceTxid string
	// issuance vout
	IssuanceVout uint32
	// is issuance asset
	IsIssuanceAsset bool
	// is issuance token
	IsIssuanceToken bool
}

/**
 * Get blind data.
 * param: blindHandle          blindTx handle
 * return: blinderList         blind data list
 * return: err                 error
 */
func CfdGoGetBlinderList(blindHandle uintptr) (blinderList []BlindData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	err = nil
	index := 0
	tempBlinderList := make([]BlindData, 2)
	for {
		if len(tempBlinderList) <= index {
			tempList := make([]BlindData, len(tempBlinderList)*2)
			copy(tempList, tempBlinderList)
			tempBlinderList = tempList
		}
		indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&tempBlinderList[index].Vout)))
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tempBlinderList[index].Amount)))
		issuanceVoutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&tempBlinderList[index].IssuanceVout)))
		ret := CfdGetBlindTxBlindData(handle, blindHandle, indexPtr, voutPtr, &tempBlinderList[index].Asset, amountPtr, &tempBlinderList[index].AssetBlindFactor, &tempBlinderList[index].ValueBlindFactor, &tempBlinderList[index].IssuanceTxid, issuanceVoutPtr, &tempBlinderList[index].IsIssuanceAsset, &tempBlinderList[index].IsIssuanceToken)
		if ret != (int)(KCfdSuccess) {
			if ret != (int)(KCfdOutOfRangeError) {
				err = convertCfdError(ret, handle)
			}
			break
		}
		index += 1
	}

	if err == nil {
		blinderList = make([]BlindData, index)
		copy(blinderList, tempBlinderList)
	}
	return blinderList, err
}

/**
 * Free blind handle.
 * param: blindHandle          blindTx handle
 * return: err                 error
 */
func CfdGoFreeBlindHandle(blindHandle uintptr) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFreeBlindHandle(handle, blindHandle)
	err = convertCfdError(ret, handle)
	return
}

/**
 * BlindRawTransaction option data struct.
 */
type CfdBlindInputData struct {
	// Txid
	Txid string
	// Vout
	Vout uint32
	// Asset
	Asset string
	// Asset BlindFactor
	AssetBlindFactor string
	// satoshi value
	Amount int64
	// Value BlindFactor
	ValueBlindFactor string
	// (option) Asset blinding key
	AssetBlindingKey string
	// (option) Token blinding key
	TokenBlindingKey string
}

/**
 * BlindRawTransaction option data struct.
 */
type CfdBlindOutputData struct {
	// txout index (-1: auto)
	Index int
	// confidential or not address
	ConfidentialAddress string
	// (optional) confidential key
	ConfidentialKey string
}

/** CfdGoBlindRawTransaction
 * Execute blindrawtransaction.
 * param: txHex              transaction hex.
 * param: txinList           txin utxo list.
 * param: txoutList          txout target list. (need nonce empty txout)
 * param: option             blindrawtransaction option.
 * return: outputTx          blindrawtransaction tx.
 * return: err               error
 */
func CfdGoBlindRawTransaction(txHex string, txinList []CfdBlindInputData, txoutList []CfdBlindOutputData, option *CfdBlindTxOption) (outputTx string, err error) {
	outputTx, _, err = CfdGoBlindRawTransactionInternal(txHex, txinList, txoutList, option, false)
	return outputTx, err
}

/** CfdGoBlindRawTransactionAndGetBlinder
 * Execute blindrawtransaction.
 * param: txHex              transaction hex.
 * param: txinList           txin utxo list.
 * param: txoutList          txout target list. (need nonce empty txout)
 * param: option             blindrawtransaction option.
 * return: outputTx          blindrawtransaction tx.
 * return: blinderList       blinder list.
 * return: err               error
 */
func CfdGoBlindRawTransactionAndGetBlinder(txHex string, txinList []CfdBlindInputData, txoutList []CfdBlindOutputData, option *CfdBlindTxOption) (outputTx string, blinderList []BlindData, err error) {
	outputTx, blinderList, err = CfdGoBlindRawTransactionInternal(txHex, txinList, txoutList, option, true)
	return outputTx, blinderList, err
}

/** CfdGoBlindRawTransactionInternal
 * Execute blindrawtransaction.
 * param: txHex              transaction hex.
 * param: txinList           txin utxo list.
 * param: txoutList          txout target list. (need nonce empty txout)
 * param: option             blindrawtransaction option.
 * param: collectBlinder     get blinder flag.
 * return: outputTx          blindrawtransaction tx.
 * return: blinderList       blinder list.
 * return: err               error
 */
func CfdGoBlindRawTransactionInternal(txHex string, txinList []CfdBlindInputData, txoutList []CfdBlindOutputData, option *CfdBlindTxOption, collectBlinder bool) (outputTx string, blinderList []BlindData, err error) {
	blinderList = []BlindData{}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return "", blinderList, err
	}
	defer CfdGoFreeHandle(handle)

	var blindHandle uintptr
	ret := CfdInitializeBlindTx(handle, &blindHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return "", blinderList, err
	}
	defer CfdFreeBlindHandle(handle, blindHandle)

	if option != nil {
		minRangeValPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&(*option).MinimumRangeValue)))
		ret := CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionMinimumRangeValue), minRangeValPtr)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}

		exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&(*option).Exponent)))
		ret = CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionExponent), exponentPtr)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}

		minBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&(*option).MinimumBits)))
		ret = CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionMinimumBits), minBitsPtr)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}
	}
	if collectBlinder {
		collectTrue := int64(1)
		collectTruePtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&collectTrue)))
		ret = CfdSetBlindTxOption(handle, blindHandle, int(KCfdBlindOptionCollectBlinder), collectTruePtr)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}
	}

	for i := 0; i < len(txinList); i++ {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinList[i].Vout)))
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txinList[i].Amount)))
		ret = CfdAddBlindTxInData(handle, blindHandle, txinList[i].Txid, voutPtr, txinList[i].Asset, txinList[i].AssetBlindFactor, txinList[i].ValueBlindFactor, amountPtr, txinList[i].AssetBlindingKey, txinList[i].TokenBlindingKey)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}
	}

	for i := 0; i < len(txoutList); i++ {
		if txoutList[i].Index < 0 {
			ret = CfdAddBlindTxOutByAddress(handle, blindHandle, txoutList[i].ConfidentialAddress)
		} else if len(txoutList[i].ConfidentialKey) > 0 {
			index := uint32(txoutList[i].Index)
			indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
			ret = CfdAddBlindTxOutData(handle, blindHandle, indexPtr, txoutList[i].ConfidentialKey)
		} else {
			var address string
			var confidentialKey string
			var networkType int
			ret = CfdParseConfidentialAddress(handle, txoutList[i].ConfidentialAddress, &address, &confidentialKey, &networkType)
			if ret != (int)(KCfdSuccess) {
				err = convertCfdError(ret, handle)
				return "", blinderList, err
			}
			index := uint32(txoutList[i].Index)
			indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
			ret = CfdAddBlindTxOutData(handle, blindHandle, indexPtr, confidentialKey)
		}
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}
	}

	ret = CfdFinalizeBlindTx(handle, blindHandle, txHex, &outputTx)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return "", blinderList, err
	}
	if collectBlinder {
		blinderList, err = CfdGoGetBlinderList(blindHandle)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return "", blinderList, err
		}
	}
	return outputTx, blinderList, nil
}

/**
 * Add sign data to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: signDataHex          sign data hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxSign(txHex string, txid string, vout uint32, isWitness bool, signDataHex string, clearStack bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Convert to der encode, and add sign data to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: signDataHex          sign data hex
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxDerSign(txHex string, txid string, vout uint32, isWitness bool, signDataHex string, sighashType int, sighashAnyoneCanPay bool, clearStack bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxDerSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, sighashType, sighashAnyoneCanPay, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add unlocking script to confidential transaction input by index.
 *   (prototype interface)
 * param: txHex                transaction hex
 * param: index                input index
 * param: isWitness            insert sign data to witness stack
 * param: unlockingScript      unlocking script hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxUnlockingScriptByIndex(txHex string, index uint32, isWitness bool, unlockingScript string, clearStack bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txid, vout, _, _, err := CfdGoGetConfidentialTxIn(txHex, index)
	if err != nil {
		return
	}
	txHexWork, err := CfdGoAddConfidentialTxUnlockingScript(txHex, txid, vout, isWitness, unlockingScript, clearStack)
	if err != nil {
		return
	}

	outputTxHex = txHexWork
	return
}

/**
 * Add unlocking script to confidential transaction input.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: unlockingScript      unlocking script hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxUnlockingScript(txHex, txid string, vout uint32, isWitness bool, unlockingScript string, clearStack bool) (outputTxHex string, err error) {
	scriptItems, err := CfdGoParseScript(unlockingScript)
	if err != nil {
		return "", err
	}

	txHexWork := txHex
	clearFlag := clearStack
	for _, scriptItem := range scriptItems {
		txHexWork, err = CfdGoAddConfidentialTxSign(txHexWork, txid, vout, isWitness, scriptItem, clearFlag)
		if err != nil {
			return "", err
		}

		if clearFlag {
			clearFlag = false
		}
	}

	outputTxHex = txHexWork
	return outputTxHex, err
}

/**
 * Add multisig sign data to confidential transaction.
 * param: multiSignHandle      multisig sign handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type
 * param: witnessScript        witness script (p2wsh, p2sh-p2wsh)
 * param: redeemScript         redeem script (p2sh, p2sh-p2wsh)
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoFinalizeElementsMultisigSign(multiSignHandle uintptr, txHex string, txid string, vout uint32, hashType int, witnessScript string, redeemScript string, clearStack bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdFinalizeElementsMultisigSign(handle, multiSignHandle, txHex, txid, voutPtr, hashType, witnessScript, redeemScript, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Create sighash from confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type
 * param: pubkey               pubkey (p2pkh, p2wpkh, p2sh-p2wpkh)
 * param: redeemScript         redeem script (p2Sh, p2wsh, p2sh-p2wsh)
 * param: satoshiAmount        amount by satoshi
 * param: valueCommitment      amount by commitment bytes.
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoCreateConfidentialSighash(txHex string, txid string, vout uint32, hashType int, pubkey string, redeemScript string, satoshiAmount int64, valueCommitment string, sighashType int, sighashAnyoneCanPay bool) (sighash string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdCreateConfidentialSighash(handle, txHex, txid, voutPtr, hashType, pubkey, redeemScript, satoshiPtr, valueCommitment, sighashType, sighashAnyoneCanPay, &sighash)
	err = convertCfdError(ret, handle)
	return sighash, err
}

/**
 * Unblind txout on confidential transaction.
 * param: txHex                transaction hex
 * param: index                txout index
 * param: blindingKey          blinding key
 * return: asset               asset
 * return: satoshiAmount       satoshi amount
 * return: assetBlindFactor    asset blind factor
 * return: valueBlindFactor    amount blind factor
 * return: err                 error
 */
func CfdGoUnblindTxOut(txHex string, index uint32, blindingKey string) (asset string, satoshiAmount int64, assetBlindFactor string, valueBlindFactor string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUnblindTxOut(handle, txHex, indexPtr, blindingKey, &asset, satoshiPtr, &assetBlindFactor, &valueBlindFactor)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, assetBlindFactor, valueBlindFactor, err
}

/**
 * Unblind txin issuance on confidential transaction.
 * param: txHex                   transaction hex
 * param: index                   txin index
 * param: assetBlindingKey        asset blinding key
 * param: tokenBlindingKey        token blinding key
 * return: asset                  asset
 * return: assetAmount            asset amount
 * return: assetBlindFactor       issueAsset asset blind factor
 * return: assetValueBlindFactor  issueAsset value blind factor
 * return: token                  token
 * return: tokenAmount            token amount
 * return: tokenBlindFactor       issueToken asset blind factor
 * return: tokenValueBlindFactor  issueToken value blind factor
 * return: err                 error
 */
func CfdGoUnblindIssuance(txHex string, index uint32, assetBlindingKey string, tokenBlindingKey string) (asset string, assetAmount int64, assetBlindFactor string, assetValueBlindFactor string, token string, tokenAmount int64, tokenBlindFactor string, tokenValueBlindFactor string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdUnblindIssuance(handle, txHex, indexPtr, assetBlindingKey, tokenBlindingKey, &asset, assetSatoshiPtr, &assetBlindFactor, &assetValueBlindFactor, &token, tokenSatoshiPtr, &tokenBlindFactor, &tokenValueBlindFactor)
	err = convertCfdError(ret, handle)
	return asset, assetAmount, assetBlindFactor, assetValueBlindFactor, token, tokenAmount, tokenBlindFactor, tokenValueBlindFactor, err
}

/**
 * Generate multisig sign handle.
 * return: multisigSignHandle  multisig sign handle. release: CfdGoFreeMultisigSignHandle
 * return: err                 error
 */
func CfdGoInitializeMultisigSign() (multisigSignHandle uintptr, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdInitializeMultisigSign(handle, &multisigSignHandle)
	err = convertCfdError(ret, handle)
	return multisigSignHandle, err
}

/**
 * Add multisig sign data.
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: relatedPubkey        signature related pubkey
 * return: err                 error
 */
func CfdGoAddMultisigSignData(multisigSignHandle uintptr, signature string, relatedPubkey string) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdAddMultisigSignData(handle, multisigSignHandle, signature, relatedPubkey)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Convert to der encode, and add multisig sign data.
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: relatedPubkey        signature related pubkey
 * return: err                 error
 */
func CfdGoAddMultisigSignDataToDer(multisigSignHandle uintptr, signature string, sighashType int, sighashAnyoneCanPay bool, relatedPubkey string) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdAddMultisigSignDataToDer(handle, multisigSignHandle, signature, sighashType, sighashAnyoneCanPay, relatedPubkey)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Free multisig sign handle.
 * param: multisigSignHandle   multisig sign handle
 * return: err                 error
 */
func CfdGoFreeMultisigSignHandle(multisigSignHandle uintptr) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFreeMultisigSignHandle(handle, multisigSignHandle)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Create confidential address.
 * param: address               address
 * param: confidentialKey       confidential key
 * return: confidentialAddress  confidential address
 * return: err                  error
 */
func CfdGoCreateConfidentialAddress(address string, confidentialKey string) (confidentialAddress string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateConfidentialAddress(handle, address, confidentialKey, &confidentialAddress)
	err = convertCfdError(ret, handle)
	return confidentialAddress, err
}

/**
 * Get address and confidentialKey from confidentialAddress.
 * param: confidentialAddress  confidential address
 * return: address             address
 * return: confidentialKey     confidential key
 * return: networkType         network type
 * return: err                 error
 */
func CfdGoParseConfidentialAddress(confidentialAddress string) (address string, confidentialKey string, networkType int, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdParseConfidentialAddress(handle, confidentialAddress,
		&address, &confidentialKey, &networkType)
	err = convertCfdError(ret, handle)
	return address, confidentialKey, networkType, err
}

/**
 * Calculate ec-signature from privkey.
 * param: sighash              signature hash
 * param: privkeyHex           privkey hex (Specify either privkeyHex or privkeyWif)
 * param: privkeyWif           privkey WIF (Specify either privkeyHex or privkeyWif)
 * param: wifNetworkType       network type (for privkey WIF)
 * param: hasGrindR            grind-r flag
 * return: signature           signature
 * return: err                 error
 */
func CfdGoCalculateEcSignature(sighash string, privkeyHex string, privkeyWif string, wifNetworkType int, hasGrindR bool) (signature string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCalculateEcSignature(handle, sighash, privkeyHex, privkeyWif, wifNetworkType, hasGrindR, &signature)
	err = convertCfdError(ret, handle)
	return signature, err
}

/**
 * Encode ec signature by der encoding.
 * param: signature               compact format signature.
 * param: sighashType             sighash type.
 * param: sighash_anyone_can_pay  flag of signing only the current input.
 * return: derSignature   signature encoded by der encodeing.
 * return: err            error
 */
func CfdGoEncodeSignatureByDer(signature string, sighashType int, sighash_anyone_can_pay bool) (derSignature string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdEncodeSignatureByDer(handle, signature, sighashType, sighash_anyone_can_pay, &derSignature)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Create key pair.
 * param: isCompress      pubkey compressed.
 * param: networkType     privkey wif network type.
 * return: pubkey         pubkey.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: err            error
 */
func CfdGoCreateKeyPair(isCompress bool, networkType int) (pubkey string, privkeyHex string, privkeyWif string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateKeyPair(handle, isCompress, networkType, &pubkey, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, handle)
	return pubkey, privkeyHex, privkeyWif, err
}

/**
 * Get privkey from WIF.
 * param: privkeyWif      privkey wif.
 * param: networkType     privkey wif network type.
 * return: privkeyHex     privkey hex.
 * return: err            error
 */
func CfdGoGetPrivkeyFromWif(privkeyWif string, networkType int) (privkeyHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPrivkeyFromWif(handle, privkeyWif, networkType, &privkeyHex)
	err = convertCfdError(ret, handle)
	return privkeyHex, err
}

/**
 * Get privkey WIF from hex.
 * param: privkeyHex      privkey hex.
 * param: networkType     privkey wif network type.
 * param: isCompress      pubkey compressed.
 * return: privkeyWif     privkey wif.
 * return: err            error
 */
func CfdGoGetPrivkeyWif(privkeyHex string, networkType int, isCompress bool) (privkeyWif string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPrivkeyWif(handle, privkeyHex, networkType, isCompress, &privkeyWif)
	err = convertCfdError(ret, handle)
	return privkeyWif, err
}

/**
 * Parse privkey WIF data.
 * param: privkeyWif      privkey wif.
 * return: privkeyHex     privkey hex.
 * return: networkType    privkey wif network type.
 * return: isCompress     pubkey compressed.
 * return: err            error
 */
func CfdGoParsePrivkeyWif(privkeyWif string) (privkeyHex string, networkType int, isCompress bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdParsePrivkeyWif(handle, privkeyWif, &privkeyHex, &networkType, &isCompress)
	err = convertCfdError(ret, handle)
	return privkeyHex, networkType, isCompress, err
}

/**
 * Get pubkey from privkey.
 * param: privkeyHex      privkey hex. (or privkeyWif)
 * param: privkeyWif      privkey wif. (or privkeyHex)
 * param: isCompress      pubkey compressed.
 * return: pubkey         pubkey hex.
 * return: err            error
 */
func CfdGoGetPubkeyFromPrivkey(privkeyHex string, privkeyWif string, isCompress bool) (pubkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPubkeyFromPrivkey(handle, privkeyHex, privkeyWif, isCompress, &pubkey)
	err = convertCfdError(ret, handle)
	return pubkey, err
}

/** CfdGoCreateExtkey
 * Create extkey.
 * param: networkType     network type.
 * param: extkeyType      extkey type. (0: privkey, 1: pubkey)
 * param: fingerprint     fingerprint.
 * param: key             key.
 * param: chainCode       chain code.
 * param: depth           depth.
 * param: childNumber     child number. (0x80000000 over is hardened.)
 * return: extkey         extkey.
 * return: err            error
 */
func CfdGoCreateExtkey(networkType int, extkeyType int, fingerprint string, key string, chainCode string, depth byte, childNumber uint32) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	childNumberPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childNumber)))
	ret := CfdCreateExtkey(handle, networkType, extkeyType, "", fingerprint, key, chainCode, depth, childNumberPtr, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

/** CfdGoCreateExtkeyFromParent
 * Create extkey from parent key.
 * param: networkType     network type.
 * param: extkeyType      extkey type. (0: privkey, 1: pubkey)
 * param: parentKey       parent key. (pubkey or privkey)
 * param: key             key. (pubkey or privkey)
 * param: chainCode       chain code.
 * param: depth           depth.
 * param: childNumber     child number. (0x80000000 over is hardened.)
 * return: extkey         extkey.
 * return: err            error
 */
func CfdGoCreateExtkeyFromParent(networkType int, extkeyType int, parentKey string, key string, chainCode string, depth byte, childNumber uint32) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	childNumberPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childNumber)))
	ret := CfdCreateExtkey(handle, networkType, extkeyType, parentKey, "", key, chainCode, depth, childNumberPtr, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

/**
 * Create extkey from seed.
 * param: seed            seed data(hex).
 * param: networkType     network type.
 * param: keyType         extkey type. (0: privkey, 1: pubkey)
 * return: extkey         extkey.
 * return: err            error
 */
func CfdGoCreateExtkeyFromSeed(seed string, networkType int, keyType int) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateExtkeyFromSeed(handle, seed, networkType, keyType, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

/**
 * Create extkey from parent path.
 * param: extkey          parent extkey.
 * param: path            bip32 key path.(ex: 0/0h/0'/0)
 * param: networkType     network type.
 * param: keyType         extkey type. (0: privkey, 1: pubkey)
 * return: childExtkey    child extkey.
 * return: err            error
 */
func CfdGoCreateExtkeyFromParentPath(extkey string, path string, networkType int, keyType int) (childExtkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateExtkeyFromParentPath(handle, extkey, path, networkType, keyType, &childExtkey)
	err = convertCfdError(ret, handle)
	return childExtkey, err
}

/**
 * Create extpubkey from extprivkey.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: extPubkey      ext pubkey.
 * return: err            error
 */
func CfdGoCreateExtPubkey(extkey string, networkType int) (extPubkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateExtPubkey(handle, extkey, networkType, &extPubkey)
	err = convertCfdError(ret, handle)
	return extPubkey, err
}

/**
 * Get privkey from extprivkey.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: err            error
 */
func CfdGoGetPrivkeyFromExtkey(extkey string, networkType int) (privkeyHex string, privkeyWif string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPrivkeyFromExtkey(handle, extkey, networkType, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, handle)
	return privkeyHex, privkeyWif, err
}

/**
 * Get pubkey from extkey.
 * param: extkey          extkey.
 * param: networkType     network type.
 * return: pubkey         pubkey.
 * return: err            error
 */
func CfdGoGetPubkeyFromExtkey(extkey string, networkType int) (pubkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPubkeyFromExtkey(handle, extkey, networkType, &pubkey)
	err = convertCfdError(ret, handle)
	return pubkey, err
}

/**
 * Get parent key path data.
 * param: parentExtkey       parent ext key string.
 * param: path               child path.
 * param: childExtkeyType    child key type. (see CfdDescriptorKeyType)
 * return: keyPathData       key path data.
 * return: childExtkey       child ext key string.
 * return: err               error
 */
func CfdGoGetParentExtkeyPathData(
	parentExtkey, path string, childExtkeyType int) (keyPathData, childExtkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetParentExtkeyPathData(handle, parentExtkey, path, childExtkeyType, &keyPathData, &childExtkey)
	err = convertCfdError(ret, handle)
	return keyPathData, childExtkey, err
}

/**
 * Extkey data struct.
 */
type CfdExtkeyData struct {
	// version
	Version string
	// parent fingerprint
	Fingerprint string
	// chain code
	ChainCode string
	// depth
	Depth uint32
	// child number
	ChildNumber uint32
}

/**
 * Get extkey information.
 * param: extkey             ext key string.
 * return: extkeyData        CfdExtkeyData
 * return: err               error
 */
func CfdGoGetExtkeyInformation(
	extkey string) (extkeyData CfdExtkeyData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&extkeyData.Depth)))
	childNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&extkeyData.ChildNumber)))
	ret := CfdGetExtkeyInformation(handle, extkey, &extkeyData.Version, &extkeyData.Fingerprint, &extkeyData.ChainCode, depthPtr, childNumPtr)
	err = convertCfdError(ret, handle)
	return extkeyData, err
}

// CfdGoGetExtkeyInfo This function returns extkey info and network.
func CfdGoGetExtkeyInfo(
	extkey string) (extkeyData CfdExtkeyData, keyType, networkType int, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&extkeyData.Depth)))
	childNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&extkeyData.ChildNumber)))
	ret := CfdGetExtkeyInfo(handle, extkey, &extkeyData.Version, &extkeyData.Fingerprint, &extkeyData.ChainCode, depthPtr, childNumPtr, &keyType, &networkType)
	err = convertCfdError(ret, handle)
	return extkeyData, keyType, networkType, err
}

/**
 * Parse script items from script.
 * param: script          script.
 * return: scriptItems    script items.
 * return: err            error
 */
func CfdGoParseScript(script string) (scriptItems []string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var scriptStr string
	ret := CfdParseScriptAll(handle, script, &scriptStr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return nil, err
	}

	scriptItems = strings.Split(scriptStr, " ")
	return scriptItems, nil
}

/**
 * Convert script asm to hex.
 * param: scriptAsm       script assembly string.
 * return: script         hex encoded script.
 * return: err            error
 */
func CfdGoConvertScriptAsmToHex(scriptAsm string) (script string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	if ret := CfdConvertScriptAsmToHex(handle, scriptAsm, &script); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		script = ""
	}

	return
}

/**
 * Create script from script items.
 * param: scriptItems     array of script element string.
 * return: script         hex encoded script.
 * return: err            error
 */
func CfdGoCreateScript(scriptItems []string) (script string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	scriptAsm := strings.Join(scriptItems, " ")
	script, err = CfdGoConvertScriptAsmToHex(scriptAsm)

	return
}

/**
 * Multisig sign data struct.
 */
type CfdMultisigSignData struct {
	// signature
	Signature string
	// use der encode
	IsDerEncode bool
	// sighash type. (CfdSighashType)
	SighashType int
	// sighash anyone can pay.
	SighashAnyoneCanPay bool
	// related pubkey.
	RelatedPubkey string
}

/**
 * Create multisig scriptsig.
 * param: signItems       array of multisig sign data struct.
 * param: redeemScript    hex encoded multisig script.
 * return: scriptsig      hex encoded script.
 * return: err            error
 */
func CfdGoCreateMultisigScriptSig(signItems []CfdMultisigSignData, redeemScript string) (scriptsig string, err error) {
	scriptsig = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var multisigHandle uintptr
	ret := CfdInitializeMultisigScriptSig(handle, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdFreeMultisigScriptSigHandle(handle, multisigHandle)

	for i := 0; i < len(signItems); i++ {
		if signItems[i].IsDerEncode {
			ret = CfdAddMultisigScriptSigDataToDer(handle, multisigHandle,
				signItems[i].Signature, signItems[i].SighashType,
				signItems[i].SighashAnyoneCanPay, signItems[i].RelatedPubkey)
		} else {
			ret = CfdAddMultisigScriptSigData(handle, multisigHandle,
				signItems[i].Signature, signItems[i].RelatedPubkey)
		}
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		ret = CfdFinalizeMultisigScriptSig(handle, multisigHandle, redeemScript, &scriptsig)
	}
	return scriptsig, convertCfdError(ret, handle)
}

/**
 * Set multisig scriptsig to locking script.
 * param: txHex         transaction hex
 * param: txid          txid
 * param: vout          vout
 * param: scriptsig     hex encoded script.
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoSetElementsMultisigScriptSig(txHex string, txid string, vout uint32, scriptsig string, hashType int) (outputTxHex string, err error) {
	outputTxHex = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	scriptsigItems, err := CfdGoParseScript(scriptsig)
	if err != nil {
		return "", err
	}
	scriptsigIndex := len(scriptsigItems)
	if scriptsigIndex < 3 {
		return "", errors.Errorf("CFD Error: message=[%s], code=[%d]", "Invalid scriptsig array length.", KCfdIllegalArgumentError)
	}

	redeemScript := ""
	witnessScript := ""
	if hashType == (int)(KCfdP2sh) {
		redeemScript = scriptsigItems[scriptsigIndex-1]
	} else if hashType == (int)(KCfdP2wsh) {
		witnessScript = scriptsigItems[scriptsigIndex-1]
	} else if hashType == (int)(KCfdP2shP2wsh) {
		witnessScript = scriptsigItems[scriptsigIndex-1]
		address := ""
		lockingScript := ""
		ret := CfdCreateAddress(handle, hashType, "", witnessScript, (int)(KCfdNetworkLiquidv1), &address, &lockingScript, &redeemScript)
		if ret != (int)(KCfdSuccess) {
			return "", convertCfdError(ret, handle)
		}
	} else {
		return "", errors.Errorf("CFD Error: message=[%s], code=[%d]", "Unsupported hashType.", KCfdIllegalArgumentError)
	}

	var multisigHandle uintptr
	ret := CfdInitializeMultisigSign(handle, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdGoFreeMultisigSignHandle(multisigHandle)

	for i := 1; i < scriptsigIndex-1; i++ {
		ret := CfdAddMultisigSignData(handle, multisigHandle, scriptsigItems[i], "")
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
		ret = CfdFinalizeElementsMultisigSign(handle, multisigHandle, txHex, txid, voutPtr, hashType, witnessScript, redeemScript, true, &outputTxHex)
	}
	return outputTxHex, convertCfdError(ret, handle)
}

/**
 * Verify signature in transaction input by index.
 *   (prototype interface)
 * param: txHex                 transaction hex.
 * param: signature             signature for input.
 * param: pubkey                pubkey hex.
 * param: script                script hex.
 * param: index                 index of input for verification.
 * param: sighashType           sighash type.
 * param: sighashAnyoneCanPay   sighash anyone can pay flag.
 * param: satoshiAmount         input satoshi amount.
 *     (used only for witness input.)
 * param: valueCommitment       input value commitment.
 *     (used only for witness input.)
 * param: witnessVersion        witness version.
 *     (used only for witness input. If not used, set KCfdWitnessVersionNone or "-1".)
 * return: result               result of verification signature
 * return: err                  error
 */
func CfdGoVerifyConfidentialTxSignatureByIndex(
	txHex, signature, pubkey, script string, index uint32,
	sighashType int, sighashAnyoneCanPay bool, satoshiAmount int64,
	valueCommitment string, witnessVersion int) (result bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txid, vout, _, _, err := CfdGoGetConfidentialTxIn(txHex, index)
	if err != nil {
		return
	}
	resultWork, err := CfdGoVerifyConfidentialTxSignature(txHex, signature,
		pubkey, script, txid, vout, sighashType, sighashAnyoneCanPay,
		satoshiAmount, valueCommitment, witnessVersion)
	if err != nil {
		return
	}

	result = resultWork
	return
}

/**
 * Verify signature in transaction input.
 * param: txHex                 transaction hex.
 * param: signature             signature for input.
 * param: pubkey                pubkey hex.
 * param: script                script hex.
 * param: txid                  input txid.
 * param: vout                  input vout.
 * param: sighashType           sighash type.
 * param: sighashAnyoneCanPay   sighash anyone can pay flag.
 * param: satoshiAmount         input satoshi amount.
 *     (used only for witness input.)
 * param: valueCommitment       input value commitment.
 *     (used only for witness input.)
 * param: witnessVersion        witness version.
 *     (used only for witness input. If not witness input used, set KCfdWitnessVersionNone or "-1".)
 * return: result               result of verification signature
 * return: err                  error
 */
func CfdGoVerifyConfidentialTxSignature(
	txHex, signature, pubkey, script, txid string, vout uint32,
	sighashType int, sighashAnyoneCanPay bool, satoshiAmount int64,
	valueCommitment string, witnessVersion int) (result bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sig := signature
	if len(signature) > (65 * 2) {
		var decodedSig string
		var decSighashType int
		var decSighashAnyoneCanPay bool
		ret := CfdDecodeSignatureFromDer(handle, signature, &decodedSig, &decSighashType, &decSighashAnyoneCanPay)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return false, err
		}
		sig = decodedSig
	}

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdVerifyConfidentialTxSignature(handle, txHex, sig,
		pubkey, script, txid, voutPtr, sighashType, sighashAnyoneCanPay,
		satoshiAmountPtr, valueCommitment, witnessVersion)

	if ret == (int)(KCfdSuccess) {
		result = true
	} else if ret == (int)(KCfdSignVerificationError) {
		result = false
	} else {
		return false, convertCfdError(ret, handle)
	}

	return
}

/**
 * Normalize ec signature to low-s form
 * param: signature              ec signature to normalize
 * return: normalizeSignature    normalized signature
 * return: err                   error
 */
func CfdGoNormalizeSignature(signature string) (normalizedSignature string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdNormalizeSignature(handle, signature, &normalizedSignature)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		normalizedSignature = ""
	}

	return
}

/**
 * Decode der encoded signature.
 * param: derEncodedSignature      signature encoded by der encodeing.
 * return: signature               compact format signature.
 * return: sighashType             sighash type.
 * return: sighashAnyoneCanPay     flag of signing only the current input.
 * return: err                     error
 */
func CfdGoDecodeSignatureFromDer(derEncodedSignature string) (signature string, sighashType int, sighashAnyoneCanPay bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdDecodeSignatureFromDer(handle, derEncodedSignature, &signature, &sighashType, &sighashAnyoneCanPay)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Generate sign with privkey, and add sign data to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type (p2pkh, p2sh, etc...)
 * param: pubkey               public key.
 * param: privkey              private key.
 * param: satoshiAmount        input satoshi amount.
 *     (used only for exist valueCommitment.)
 * param: valueCommitment      input value commitment.
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: hasGrindR            grind-r option for ec-signature.
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxSignWithPrivkey(txHex string, txid string, vout uint32, hashType int, pubkey string, privkey string, satoshiAmount int64, valueCommitment string, sighashType int, sighashAnyoneCanPay bool, hasGrindR bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxSignWithPrivkeySimple(handle, txHex, txid, voutPtr, hashType, pubkey, privkey, satoshiAmountPtr, valueCommitment, sighashType, sighashAnyoneCanPay, hasGrindR, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Sign parameter data struct.
 */
type CfdSignParameter struct {
	// data hex
	Data string
	// use der encode
	IsDerEncode bool
	// sighash type. (CfdSighashType)
	SighashType int
	// sighash anyone can pay.
	SighashAnyoneCanPay bool
}

/**
 * Add pubkey hash sign data to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type (p2pkh, p2sh, etc...)
 * param: pubkey               public key.
 * param: CfdSignatureData     signature data.
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxPubkeyHashSign(txHex string, txid string, vout uint32, hashType int, pubkey string, signatureData CfdSignParameter) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddPubkeyHashSign(handle, (int)(KCfdNetworkLiquidv1), txHex, txid, voutPtr, hashType, pubkey, signatureData.Data, signatureData.IsDerEncode, signatureData.SighashType, signatureData.SighashAnyoneCanPay, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add script hash sign data to confidential transaction.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type (p2pkh, p2sh, etc...)
 * param: signDataList         sign data list.
 * param: redeemScript         redeem script.
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxScriptHashSign(txHex string, txid string, vout uint32, hashType int, signDataList []CfdSignParameter, redeemScript string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := (int)(KCfdSuccess)
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	workTxHex := txHex
	workOutputTxHex := ""
	netType := (int)(KCfdNetworkLiquidv1)
	clearFlag := true
	for i := 0; i < len(signDataList); i++ {
		ret = CfdAddTxSign(handle, netType, workTxHex, txid, voutPtr, hashType, signDataList[i].Data, signDataList[i].IsDerEncode, signDataList[i].SighashType, signDataList[i].SighashAnyoneCanPay, clearFlag, &workOutputTxHex)
		if ret != (int)(KCfdSuccess) {
			break
		}
		workTxHex = workOutputTxHex
		workOutputTxHex = ""
		clearFlag = false
	}

	if ret == (int)(KCfdSuccess) {
		ret = CfdAddScriptHashSign(handle, netType, workTxHex, txid, voutPtr, hashType, redeemScript, clearFlag, &outputTxHex)
	}

	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add multisig sign to confidential transaction.
 * param: txHex         transaction hex
 * param: txid          txin txid
 * param: vout          txin vout
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * param: signDataList  multisig sign data list.
 * param: redeemScript  multisig redeem script.
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoAddConfidentialTxMultisigSign(txHex string, txid string, vout uint32, hashType int, signDataList []CfdMultisigSignData, redeemScript string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var multisigHandle uintptr
	ret := CfdInitializeMultisigSign(handle, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdFreeMultisigSignHandle(handle, multisigHandle)

	for i := 0; i < len(signDataList); i++ {
		if signDataList[i].IsDerEncode {
			ret = CfdAddMultisigSignDataToDer(handle, multisigHandle,
				signDataList[i].Signature, signDataList[i].SighashType,
				signDataList[i].SighashAnyoneCanPay, signDataList[i].RelatedPubkey)
		} else {
			ret = CfdAddMultisigSignData(handle, multisigHandle,
				signDataList[i].Signature, signDataList[i].RelatedPubkey)
		}
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
		ret = CfdFinalizeMultisigSign(handle, multisigHandle, (int)(KCfdNetworkLiquidv1), txHex, txid, voutPtr, hashType, redeemScript, &outputTxHex)
	}
	return outputTxHex, convertCfdError(ret, handle)
}

/**
 * Verify sign in transaction input.
 * param: txHex                transaction hex.
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: address              address string.
 * param: addressType          address type.
 * param: directLockingScript  locking script direct input.
 * param: satoshiAmount        input satoshi amount.
 *     (used only for exist valueCommitment.)
 * param: valueCommitment      input value commitment.
 * return: isSuccess           result of verification signature
 * return: err                 error
 */
func CfdGoVerifyConfidentialTxSign(txHex string, txid string, vout uint32, address string, addressType int, directLockingScript string, satoshiAmount int64, valueCommitment string) (isSuccess bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdVerifyConfidentialTxSign(handle, txHex, txid, voutPtr, address, addressType, directLockingScript, satoshiAmountPtr, valueCommitment)
	if ret == (int)(KCfdSuccess) {
		isSuccess = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isSuccess = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isSuccess, err
}

/**
 * Verify sign in transaction input with error message.
 * param: txHex                transaction hex.
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: address              address string.
 * param: addressType          address type.
 * param: directLockingScript  locking script direct input.
 * param: satoshiAmount        input satoshi amount.
 *     (used only for exist valueCommitment.)
 * param: valueCommitment      input value commitment.
 * return: isSuccess           result of verification signature
 * return: reason              output error message.
 * return: err                 error
 */
func CfdGoVerifyConfidentialTxSignReason(txHex string, txid string, vout uint32, address string, addressType int, directLockingScript string, satoshiAmount int64, valueCommitment string) (isSuccess bool, reason string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdVerifyConfidentialTxSign(handle, txHex, txid, voutPtr, address, addressType, directLockingScript, satoshiAmountPtr, valueCommitment)
	if ret == (int)(KCfdSuccess) {
		isSuccess = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isSuccess = false
		CfdGetLastErrorMessage(handle, &reason)
	} else {
		err = convertCfdError(ret, handle)
		CfdGetLastErrorMessage(handle, &reason)
	}
	return isSuccess, reason, err
}

/*
 * Output data struct.
 */
type CfdOutputData struct {
	// asset
	Asset string
	// amount
	Amount int64
	// address (not implements)
	Address string
	// locking script (not implements)
	LockingScript string
}

/**
 * Serialize transaction for ledger.
 * param: txHex                  transaction hex.
 * param: isAuthorization        authorization flag.
 * param: skipWitness            skip output witness flag.
 * return: serializeData         serialize data. (sha256 hash)
 * return: err                   error
 */
func CfdGoSerializeTxForLedger(txHex string, isAuthorization bool, skipWitness bool) (serializeData string, err error) {
	serializeData = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var serializeHandle uintptr
	ret := CfdInitializeTxSerializeForLedger(handle, &serializeHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdFreeTxSerializeForLedger(handle, serializeHandle)

	ret = CfdFinalizeTxSerializeForLedger(handle, serializeHandle, (int)(KCfdNetworkLiquidv1), txHex, skipWitness, isAuthorization, &serializeData)
	err = convertCfdError(ret, handle)
	return serializeData, err
}

/**
 * Decode transaction hex.
 * param: txHex        transaction hex.
 * param: nettype      nettype string. (mainnet/testnet/regtest)
 * param: isElements   elements mode flag.
 * return: jsonString  response json string.
 * return: err         error
 */
func CfdGoDecodeRawTransactionJson(txHex string, netType string, isElements bool) (jsonString string, err error) {
	jsonString = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	cmdName := "DecodeRawTransaction"
	networkStr := netType
	mainchainNetworkStr := "regtest"
	if isElements {
		cmdName = "ElementsDecodeRawTransaction"
		if networkStr == "liquidv1" {
			mainchainNetworkStr = "mainnet"
		} else if networkStr == "mainnet" {
			networkStr = "liquidv1"
			mainchainNetworkStr = "mainnet"
		} else {
			networkStr = "regtest"
		}
	}
	requestJson := fmt.Sprintf(
		"{\"hex\":\"%s\",\"network\":\"%s\",\"mainchainNetwork\":\"%s\"}",
		txHex, networkStr, mainchainNetworkStr)

	ret := CfdRequestExecuteJson(handle, cmdName, requestJson, &jsonString)
	err = convertCfdError(ret, handle)
	return jsonString, err
}

/**
 * initialize bitcoin createrawtransaction with version & locktime.
 * param: version          transaction version.
 * param: locktime         transaction lock time.
 * return: createTxHandle  handle of createrawtransaction.
 * return: err             error
 */
func CfdGoInitializeTransaction(version uint32, locktime uint32) (createTxHandle uintptr, err error) {
	return InitializeTransaction(int(KCfdNetworkMainnet), version, locktime)
}

/**
 * initialize bitcoin createrawtransaction with hex.
 * param: txHex            transaction hex.
 * return: createTxHandle  handle of createrawtransaction.
 * return: err             error
 */
func CfdGoInitializeTransactionByHex(txHex string) (createTxHandle uintptr, err error) {
	return InitializeTransactionByHex(int(KCfdNetworkMainnet), txHex)
}

/**
 * initialize elements createrawtransaction with version & locktime.
 * param: version          transaction version.
 * param: locktime         transaction lock time.
 * return: createTxHandle  handle of createrawtransaction.
 * return: err             error
 */
func CfdGoInitializeConfidentialTransaction(version uint32, locktime uint32) (createTxHandle uintptr, err error) {
	return InitializeTransaction(int(KCfdNetworkLiquidv1), version, locktime)
}

/**
 * initialize elements createrawtransaction with hex.
 * param: txHex            transaction hex.
 * return: createTxHandle  handle of createrawtransaction.
 * return: err             error
 */
func CfdGoInitializeConfidentialTransactionByHex(txHex string) (createTxHandle uintptr, err error) {
	return InitializeTransactionByHex(int(KCfdNetworkLiquidv1), txHex)
}

/**
 * add transaction input. (bitcoin and elements)
 * param: createTxHandle   handle of createrawtransaction.
 * param: txid             txid of utxo.
 * param: vout             vout of utxo.
 * param: sequence         sequence number.
 * return: err             error
 */
func CfdGoAddTxInput(createTxHandle uintptr, txid string, vout uint32, sequence uint32) (err error) {
	return AddTransactionInput(createTxHandle, txid, vout, sequence)
}

/**
 * add transaction output for bitcoin.
 * param: createTxHandle   handle of createrawtransaction.
 * param: amount           amount by satoshi.
 * param: address          sending address.
 * return: err             error
 */
func CfdGoAddTxOutput(createTxHandle uintptr, amount int64, address string) (err error) {
	return AddTransactionOutput(createTxHandle, amount, address, "", "")
}

/**
 * add transaction output by locking script for bitcoin.
 * param: createTxHandle   handle of createrawtransaction.
 * param: amount           amount by satoshi.
 * param: lockingScript    locking script.
 * return: err             error
 */
func CfdGoAddTxOutputByScript(createTxHandle uintptr, amount int64, lockingScript string) (err error) {
	return AddTransactionOutput(createTxHandle, amount, "", lockingScript, "")
}

/**
 * add transaction output for elements.
 * param: createTxHandle   handle of createrawtransaction.
 * param: asset            target asset.
 * param: amount           amount by satoshi.
 * param: address          sending address.
 * return: err             error
 */
func CfdGoAddConfidentialTxOutput(createTxHandle uintptr, asset string, amount int64, address string) (err error) {
	return AddTransactionOutput(createTxHandle, amount, address, "", asset)
}

/**
 * add transaction output by locking script for elements.
 * param: createTxHandle   handle of createrawtransaction.
 * param: asset            target asset.
 * param: amount           amount by satoshi.
 * param: lockingScript    locking script.
 * return: err             error
 */
func CfdGoAddConfidentialTxOutputByScript(createTxHandle uintptr, asset string, amount int64, lockingScript string) (err error) {
	return AddTransactionOutput(createTxHandle, amount, "", lockingScript, asset)
}

/**
 * add transaction output by fee for elements.
 * param: createTxHandle   handle of createrawtransaction.
 * param: asset            target asset.
 * param: amount           amount by satoshi.
 * return: err             error
 */
func CfdGoAddConfidentialTxOutputFee(createTxHandle uintptr, asset string, amount int64) (err error) {
	return AddTransactionOutput(createTxHandle, amount, "", "", asset)
}

/**
 * add transaction output for destroy amount.
 * param: createTxHandle   handle of createrawtransaction.
 * param: asset            target asset.
 * param: amount           amount by satoshi.
 * return: err             error
 */
func CfdGoAddConfidentialTxOutputDestroyAmount(createTxHandle uintptr, asset string, amount int64) (err error) {
	burnScript, err := CfdGoConvertScriptAsmToHex("OP_RETURN") // byte of OP_RETURN
	if err != nil {
		return err
	}
	return AddTransactionOutput(createTxHandle, amount, "", burnScript, asset)
}

/**
 * finalize transaction.
 * param: createTxHandle   handle of createrawtransaction.
 * return: txHex           transaction hex.
 * return: err             error
 */
func CfdGoFinalizeTransaction(createTxHandle uintptr) (txHex string, err error) {
	return FinalizeTransaction(createTxHandle)
}

/**
 * free transaction handle.
 * param: createTxHandle   handle of createrawtransaction.
 */
func CfdGoFreeTransactionHandle(createTxHandle uintptr) {
	FreeTransactionHandle(createTxHandle)
}

/** CfdGoSerializeByteData
 * Serialize byte data.
 * param: buffer        buffer
 * return: output       serialized buffer.
 * return: err          error
 */
func CfdGoSerializeByteData(buffer string) (output string, err error) {
	output = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdSerializeByteData(handle, buffer, &output)
	err = convertCfdError(ret, handle)
	return output, err
}

/** CfdGoVerifyEcSignature
 * Verify ec signature.
 * param: sighash       signature hash.
 * param: pubkey        pubkey.
 * param: signature     signature.
 * return: isVerify     verify check.
 * return: err          error
 */
func CfdGoVerifyEcSignature(sighash string, pubkey string, signature string) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifyEcSignature(handle, sighash, pubkey, signature)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

/** CfdGoCompressPubkey
 * Compress pubkey.
 * param: pubkey              pubkey.
 * return: compressedPubkey   compressed pubkey.
 * return: err                error
 */
func CfdGoCompressPubkey(pubkey string) (compressedPubkey string, err error) {
	compressedPubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCompressPubkey(handle, pubkey, &compressedPubkey)
	err = convertCfdError(ret, handle)
	return compressedPubkey, err
}

/** CfdGoUncompressPubkey
 * Compress pubkey.
 * param: pubkey                pubkey.
 * return: uncompressedPubkey   uncompressed pubkey.
 * return: err                  error
 */
func CfdGoUncompressPubkey(pubkey string) (uncompressedPubkey string, err error) {
	uncompressedPubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdUncompressPubkey(handle, pubkey, &uncompressedPubkey)
	err = convertCfdError(ret, handle)
	return uncompressedPubkey, err
}

/** CfdGoCombinePubkey
 * Combine pubkey.
 * param: pubkeyList          pubkey list.
 * return: combinedPubkey     combined pubkey.
 * return: err                error
 */
func CfdGoCombinePubkey(pubkeyList []string) (combinedPubkey string, err error) {
	combinedPubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var combineHandle uintptr
	ret := CfdInitializeCombinePubkey(handle, &combineHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdFreeCombinePubkeyHandle(handle, combineHandle)

	for i := 0; i < len(pubkeyList); i++ {
		ret = CfdAddCombinePubkey(handle, combineHandle, pubkeyList[i])
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		ret = CfdFinalizeCombinePubkey(handle, combineHandle, &combinedPubkey)
	}
	return combinedPubkey, convertCfdError(ret, handle)
}

/** CfdGoCombinePubkeyPair
 * Compress pubkey.
 * param: sourcePubkey        source pubkey.
 * param: destPubkey          destination pubkey.
 * return: combinedPubkey     combined pubkey.
 * return: err                error
 */
func CfdGoCombinePubkeyPair(sourcePubkey string, destPubkey string) (combinedPubkey string, err error) {
	pubkeys := []string{sourcePubkey, destPubkey}
	combinedPubkey, err = CfdGoCombinePubkey(pubkeys)
	return combinedPubkey, err
}

/** CfdGoPubkeyTweakAdd
 * TweakAdd pubkey.
 * param: pubkey              pubkey.
 * param: tweak               tweak data.
 * return: tweakedPubkey      tweaked pubkey.
 * return: err                error
 */
func CfdGoPubkeyTweakAdd(pubkey string, tweak string) (tweakedPubkey string, err error) {
	tweakedPubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdPubkeyTweakAdd(handle, pubkey, tweak, &tweakedPubkey)
	err = convertCfdError(ret, handle)
	return tweakedPubkey, err
}

/** CfdGoPubkeyTweakMul
 * TweakMul pubkey.
 * param: pubkey              pubkey.
 * param: tweak               tweak data.
 * return: tweakedPubkey      tweaked pubkey.
 * return: err                error
 */
func CfdGoPubkeyTweakMul(pubkey string, tweak string) (tweakedPubkey string, err error) {
	tweakedPubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdPubkeyTweakMul(handle, pubkey, tweak, &tweakedPubkey)
	err = convertCfdError(ret, handle)
	return tweakedPubkey, err
}

/** CfdGoNegatePubkey
 * Negate pubkey.
 * param: pubkey              pubkey.
 * return: negatePubkey       negate pubkey.
 * return: err                error
 */
func CfdGoNegatePubkey(pubkey string) (negatePubkey string, err error) {
	negatePubkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdNegatePubkey(handle, pubkey, &negatePubkey)
	err = convertCfdError(ret, handle)
	return negatePubkey, err
}

/** CfdGoPrivkeyTweakAdd
 * TweakAdd privkey.
 * param: privkey             privkey.
 * param: tweak               tweak data.
 * return: tweakedPrivkey     tweaked privkey.
 * return: err                error
 */
func CfdGoPrivkeyTweakAdd(privkey string, tweak string) (tweakedPrivkey string, err error) {
	tweakedPrivkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdPrivkeyTweakAdd(handle, privkey, tweak, &tweakedPrivkey)
	err = convertCfdError(ret, handle)
	return tweakedPrivkey, err
}

/** CfdGoPrivkeyTweakMul
 * TweakMul privkey.
 * param: privkey             privkey.
 * param: tweak               tweak data.
 * return: tweakedPrivkey     tweaked privkey.
 * return: err                error
 */
func CfdGoPrivkeyTweakMul(privkey string, tweak string) (tweakedPrivkey string, err error) {
	tweakedPrivkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdPrivkeyTweakMul(handle, privkey, tweak, &tweakedPrivkey)
	err = convertCfdError(ret, handle)
	return tweakedPrivkey, err
}

/** CfdGoNegatePrivkey
 * Negate privkey.
 * param: privkey             privkey.
 * return: negatePrivkey      negate privkey.
 * return: err                error
 */
func CfdGoNegatePrivkey(privkey string) (negatePrivkey string, err error) {
	negatePrivkey = ""
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdNegatePrivkey(handle, privkey, &negatePrivkey)
	err = convertCfdError(ret, handle)
	return negatePrivkey, err
}

/** CfdGoVerifySignature
 * Verify signature.
 * param: networkType           network type.
 * param: txHex                 transaction hex.
 * param: signature             signature.
 * param: hashType              hash type.
 * param: pubkey                public key.
 * param: redeemScript          redeem script(using script hash).
 * param: txid                  utxo txid.
 * param: vout                  utxo vout.
 * param: sighashType           signature hash type.
 * param: sighashAnyoneCanPay   sighash anyone can pay flag.
 * param: satoshiValue          satoshi value.
 * param: valueByteData         value bytedata(commitment value).
 * return: isVerify             verify check.
 * return: err                  error
 */
func CfdGoVerifySignature(networkType int, txHex string, signature string, hashType int, pubkey string, redeemScript string, txid string, vout uint32, sighashType int, sighashAnyoneCanPay bool, satoshiValue int64, valueByteData string) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sig := signature
	if len(signature) > (65 * 2) {
		var decodedSig string
		var decSighashType int
		var decSighashAnyoneCanPay bool
		ret := CfdDecodeSignatureFromDer(handle, signature, &decodedSig, &decSighashType, &decSighashAnyoneCanPay)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return false, err
		}
		sig = decodedSig
	}

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiValue)))
	ret := CfdVerifySignature(handle, networkType, txHex, sig, hashType, pubkey, redeemScript, txid, voutPtr, sighashType, sighashAnyoneCanPay, satoshiPtr, valueByteData)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

/** CfdGoVerifyTxSign
 * Verify transaction sign.
 * param: networkType           network type.
 * param: txHex                 transaction hex.
 * param: txid                  utxo txid.
 * param: vout                  utxo vout.
 * param: address               address string.
 * param: addressType           address type.
 * param: directLockingScript   locking script on direct.
 * param: satoshiValue          satoshi value.
 * param: valueByteData         value bytedata(commitment value).
 * return: isVerify             verify check.
 * return: err                  error
 */
func CfdGoVerifyTxSign(networkType int, txHex string, txid string, vout uint32, address string, addressType int, directLockingScript string, satoshiValue int64, valueByteData string) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiValue)))
	ret := CfdVerifyTxSign(handle, networkType, txHex, txid, voutPtr, address, addressType, directLockingScript, satoshiPtr, valueByteData)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

/** CfdGoVerifyTxSignReason
 * Verify transaction sign.
 * param: networkType           network type.
 * param: txHex                 transaction hex.
 * param: txid                  utxo txid.
 * param: vout                  utxo vout.
 * param: address               address string.
 * param: addressType           address type.
 * param: directLockingScript   locking script on direct.
 * param: satoshiValue          satoshi value.
 * param: valueByteData         value bytedata(commitment value).
 * return: isVerify             verify check.
 * return: reason               output error message.
 * return: err                  error
 */
func CfdGoVerifyTxSignReason(networkType int, txHex string, txid string, vout uint32, address string, addressType int, directLockingScript string, satoshiValue int64, valueByteData string) (isVerify bool, reason string, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiValue)))
	ret := CfdVerifyTxSign(handle, networkType, txHex, txid, voutPtr, address, addressType, directLockingScript, satoshiPtr, valueByteData)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
		CfdGetLastErrorMessage(handle, &reason)
	} else {
		err = convertCfdError(ret, handle)
		CfdGetLastErrorMessage(handle, &reason)
	}
	return isVerify, reason, err
}

/**
 * Get transaction data.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * return: data         transaction data
 * return: err          error
 */
func CfdGoGetTxInfo(networkType int, txHex string) (data CfdTxData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetTxInfo(handle, networkType, txHex, &data.Txid, &data.Wtxid, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, handle)
	return data, err
}

/**
 * Get txin on transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: index         txin index
 * return: txid         txid
 * return: vout         vout
 * return: sequence     sequence
 * return: scriptSig    unlockingScript
 * return: err          error
 */
func CfdGoGetTxIn(networkType int, txHex string, index uint32) (txid string, vout uint32, sequence uint32, scriptSig string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetTxIn(handle, networkType, txHex, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	err = convertCfdError(ret, handle)
	return txid, vout, sequence, scriptSig, err
}

/**
 * Get witness stack on transaction input.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * param: stackIndex    witness stack index
 * return: stackData    witness stack data
 * return: err          error
 */
func CfdGoGetTxInWitness(networkType int, txHex string, txinIndex uint32, stackIndex uint32) (stackData string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetTxInWitness(handle, networkType, txHex, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, handle)
	return stackData, err
}

/**
 * Get txout on transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: index         txin index
 * return: asset            asset
 * return: satoshiAmount    amount by satoshi
 * return: valueCommitment  amount by commitment bytes.
 * return: nonce            confidential nonce
 * return: lockingScript    locking script
 * return: err              error
 */
func CfdGoGetTxOut(networkType int, txHex string, index uint32) (satoshiAmount int64, lockingScript string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetTxOut(handle, networkType, txHex, indexPtr, satoshiPtr, &lockingScript)
	err = convertCfdError(ret, handle)
	return satoshiAmount, lockingScript, err
}

/**
 * Get txin count on transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * return: count        txin count
 * return: err          error
 */
func CfdGoGetTxInCount(networkType int, txHex string) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxInCount(handle, networkType, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get witness stack count on transaction input.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * return: count        witness stack count
 * return: err          error
 */
func CfdGoGetTxInWitnessCount(networkType int, txHex string, txinIndex uint32) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxInWitnessCount(handle, networkType, txHex, txinIndexPtr, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get txout count on transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * return: count        txout count
 * return: err          error
 */
func CfdGoGetTxOutCount(networkType int, txHex string) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxOutCount(handle, networkType, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get txin index on transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: txid          transaction id
 * param: vout          transaction vout
 * return: index        txin index
 * return: err          error
 */
func CfdGoGetTxInIndex(networkType int, txHex string, txid string, vout uint32) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTxInIndex(handle, networkType, txHex, txid, voutPtr, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

/**
 * Get txout index on transaction.
 * param: networkType          network type.
 * param: txHex                transaction hex
 * param: address              address string
 * param: directLockingScript  lockingScript (if address is empty)
 * return: index               txout index
 * return: err                 error
 */
func CfdGoGetTxOutIndex(networkType int, txHex string, address string, directLockingScript string) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTxOutIndex(handle, networkType, txHex, address, directLockingScript, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

/**
 * Update txout amount on transaction.
 * param: networkType          network type.
 * param: txHex                transaction hex
 * param: index                txout index
 * param: amount               txout amount
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoUpdateTxOutAmount(networkType int, txHex string, index uint32, amount int64) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdUpdateTxOutAmount(handle, networkType, txHex, indexPtr, amountPtr, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Create sighash from transaction.
 * param: networkType          network type.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type
 * param: pubkey               pubkey (p2pkh, p2wpkh, p2sh-p2wpkh)
 * param: redeemScript         redeem script (p2Sh, p2wsh, p2sh-p2wsh)
 * param: satoshiAmount        amount by satoshi
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * return: sighash             signature hash
 * return: err                 error
 */
func CfdGoCreateSighash(networkType int, txHex string, txid string, vout uint32, hashType int, pubkey string, redeemScript string, satoshiAmount int64, sighashType int, sighashAnyoneCanPay bool) (sighash string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdCreateSighash(handle, networkType, txHex, txid, voutPtr, hashType, pubkey, redeemScript, satoshiPtr, sighashType, sighashAnyoneCanPay, &sighash)
	err = convertCfdError(ret, handle)
	return sighash, err
}

/**
 * Generate sign with privkey, and add sign data to confidential transaction.
 * param: networkType          network type.
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type (p2pkh, p2sh, etc...)
 * param: pubkey               public key.
 * param: privkey              private key.
 * param: satoshiAmount        input satoshi amount.
 *     (used only for exist valueCommitment.)
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: hasGrindR            grind-r option for ec-signature.
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddTxSignWithPrivkey(networkType int, txHex string, txid string, vout uint32, hashType int, pubkey string, privkey string, satoshiAmount int64, sighashType int, sighashAnyoneCanPay bool, hasGrindR bool) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddSignWithPrivkeySimple(handle, networkType, txHex, txid, voutPtr, hashType, pubkey, privkey, satoshiAmountPtr, sighashType, sighashAnyoneCanPay, hasGrindR, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add pubkey hash sign data to transaction.
 * param: networkType    network type.
 * param: txHex          transaction hex
 * param: txid           txin txid
 * param: vout           txin vout
 * param: hashType       hash type (p2pkh, p2sh, etc...)
 * param: pubkey         public key.
 * param: signatureData  signature data.
 * return: outputTxHex   output transaction hex
 * return: err           error
 */
func CfdGoAddTxPubkeyHashSign(networkType int, txHex string, txid string, vout uint32, hashType int, pubkey string, signatureData CfdSignParameter) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddPubkeyHashSign(handle, networkType, txHex, txid, voutPtr, hashType, pubkey, signatureData.Data, signatureData.IsDerEncode, signatureData.SighashType, signatureData.SighashAnyoneCanPay, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add script hash sign data to transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: txid          txin txid
 * param: vout          txin vout
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * param: signDataList  sign data list.
 * param: redeemScript  redeem script.
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoAddTxScriptHashSign(networkType int, txHex string, txid string, vout uint32, hashType int, signDataList []CfdSignParameter, redeemScript string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := (int)(KCfdSuccess)
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	workTxHex := txHex
	workOutputTxHex := ""
	clearFlag := true
	for i := 0; i < len(signDataList); i++ {
		ret = CfdAddTxSign(handle, networkType, workTxHex, txid, voutPtr, hashType, signDataList[i].Data, signDataList[i].IsDerEncode, signDataList[i].SighashType, signDataList[i].SighashAnyoneCanPay, clearFlag, &workOutputTxHex)
		if ret != (int)(KCfdSuccess) {
			break
		}
		workTxHex = workOutputTxHex
		workOutputTxHex = ""
		clearFlag = false
	}

	if ret == (int)(KCfdSuccess) {
		ret = CfdAddScriptHashSign(handle, networkType, workTxHex, txid, voutPtr, hashType, redeemScript, clearFlag, &outputTxHex)
	}

	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add multisig sign to transaction.
 * param: networkType   network type.
 * param: txHex         transaction hex
 * param: txid          txin txid
 * param: vout          txin vout
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * param: signDataList  multisig sign data list.
 * param: redeemScript  multisig redeem script.
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoAddTxMultisigSign(networkType int, txHex string, txid string, vout uint32, hashType int, signDataList []CfdMultisigSignData, redeemScript string) (outputTxHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var multisigHandle uintptr
	ret := CfdInitializeMultisigSign(handle, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, handle)
	}
	defer CfdFreeMultisigSignHandle(handle, multisigHandle)

	for i := 0; i < len(signDataList); i++ {
		if signDataList[i].IsDerEncode {
			ret = CfdAddMultisigSignDataToDer(handle, multisigHandle,
				signDataList[i].Signature, signDataList[i].SighashType,
				signDataList[i].SighashAnyoneCanPay, signDataList[i].RelatedPubkey)
		} else {
			ret = CfdAddMultisigSignData(handle, multisigHandle,
				signDataList[i].Signature, signDataList[i].RelatedPubkey)
		}
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
		ret = CfdFinalizeMultisigSign(handle, multisigHandle, networkType, txHex, txid, voutPtr, hashType, redeemScript, &outputTxHex)
	}
	return outputTxHex, convertCfdError(ret, handle)
}

/** CfdGoGetMnemonicWordList
 * Get mnemonic word list.
 * param: language        language. (default: en)
 * return: mnemonicList   mnemonic word list.
 * return: err            error
 */
func CfdGoGetMnemonicWordList(language string) (mnemonicList []string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var mnemonicWords string
	ret := CfdGetMnemonicWords(handle, language, &mnemonicWords)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	mnemonicList = strings.Split(mnemonicWords, " ")
	return mnemonicList, nil
}

/** CfdGoConvertMnemonicWordsToSeed
 * Convert mnemonic to seed.
 * param: mnemonicWords   mnemonic word array.
 * param: passphrase      passphrase
 * param: language        language. (default: en)
 * return: seed           seed hex.
 * return: entropy        entropy hex.
 * return: err            error
 */
func CfdGoConvertMnemonicWordsToSeed(mnemonicWords []string, passphrase string, language string) (seed string, entropy string, err error) {
	mnemonic := strings.Join(mnemonicWords, " ")
	seed, entropy, err = CfdGoConvertMnemonicToSeed(mnemonic, passphrase, language)
	return seed, entropy, err
}

/** CfdGoConvertMnemonicToSeed
 * Convert mnemonic to seed.
 * param: mnemonic        mnemonic string. (split space)
 * param: passphrase      passphrase
 * param: language        language. (default: en)
 * return: seed           seed hex.
 * return: entropy        mnemonic's entropy hex.
 * return: err            error
 */
func CfdGoConvertMnemonicToSeed(mnemonic string, passphrase string, language string) (seed string, entropy string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdConvertMnemonicToSeed(handle, mnemonic, passphrase, true, language, false, &seed, &entropy)
	err = convertCfdError(ret, handle)
	return seed, entropy, err
}

/** CfdGoConvertEntropyToMnemonic
 * Convert entropy to mnemonic.
 * param: entropy         entropy hex.
 * param: language        language. (default: en)
 * return: mnemonic       mnemonic string. (split space)
 * return: err            error
 */
func CfdGoConvertEntropyToMnemonic(entropy string, language string) (mnemonic string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdConvertEntropyToMnemonic(handle, entropy, language, &mnemonic)
	err = convertCfdError(ret, handle)
	return mnemonic, err
}

/**
 * FundRawTransaction option data struct.
 */
type CfdFundRawTxOption struct {
	// fee asset
	FeeAsset string
	// use blind tx
	IsBlindTx bool
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value. knapsack logic's threshold. Recommended value is 1.
	KnapsackMinChange int64
	// blind exponent. default is 0.
	Exponent int64
	// blind minimum bits. default is -1 (cfd-go auto).
	MinimumBits int64
}

/**
 * Selection target amount struct.
 */
type CfdFundRawTxTargetAmount struct {
	// Amount more than the specified amount is set in txout. default is 0 (disable).
	Amount int64
	// asset
	Asset string
	// address for adding txout. Also serves as a change address.
	ReservedAddress string
}

/** NewCfdFundRawTxOption
 * Create CfdFundRawTxOption struct set default value.
 * param: networkType   network type.
 * return: option       FundRawTx option
 */
func NewCfdFundRawTxOption(networkType int) CfdFundRawTxOption {
	option := CfdFundRawTxOption{}
	if networkType == int(KCfdNetworkLiquidv1) || networkType == int(KCfdNetworkElementsRegtest) {
		option.FeeAsset = "0000000000000000000000000000000000000000000000000000000000000000"
		option.IsBlindTx = true
		option.EffectiveFeeRate = float64(0.15)
		option.LongTermFeeRate = float64(-1.0)
		option.DustFeeRate = float64(-1.0)
		option.KnapsackMinChange = int64(-1)
		option.Exponent = int64(0)
		option.MinimumBits = int64(-1)
	} else {
		option.EffectiveFeeRate = float64(20.0)
		option.LongTermFeeRate = float64(-1.0)
		option.DustFeeRate = float64(-1.0)
		option.KnapsackMinChange = int64(-1)
	}
	return option
}

/** CfdGoFundRawTransactionBtc
 * Execute fundrawtransacdtion on bitcoin.
 * param: networkType        network type.
 * param: txHex              transaction hex.
 * param: txinList           txin utxo list.
 * param: utxoList           utxo list.
 * param: targetAmount       target amount. see: CfdFundRawTxTargetAmount.Amount
 * param: reservedAddress    address for adding txout. Also serves as a change address.
 * param: option             fundrawtransaction option.
 * return: outputTx          fundrawtransaction tx.
 * return: fee               fee amount.
 * return: usedAddressList   used address list.
 * return: err               error
 */
func CfdGoFundRawTransactionBtc(txHex string, txinList []CfdUtxo, utxoList []CfdUtxo, targetAmount int64, reservedAddress string, option *CfdFundRawTxOption) (outputTx string, fee int64, usedAddressList []string, err error) {
	targetAmountList := []CfdFundRawTxTargetAmount{
		{
			Amount:          targetAmount,
			Asset:           "",
			ReservedAddress: reservedAddress,
		},
	}
	outputTx, fee, usedAddressList, err = CfdGoFundRawTransaction(int(KCfdNetworkMainnet), txHex, txinList, utxoList, targetAmountList, option)
	return outputTx, fee, usedAddressList, err
}

/** CfdGoFundRawTransaction
 * Execute fundrawtransacdtion.
 * param: networkType        network type.
 * param: txHex              transaction hex.
 * param: txinList           txin utxo list.
 * param: utxoList           utxo list.
 * param: targetAmountList   selection target amount list.
 * param: option             fundrawtransaction option.
 * return: outputTx          fundrawtransaction tx.
 * return: fee               fee amount.
 * return: usedAddressList   used address list.
 * return: err               error
 */
func CfdGoFundRawTransaction(networkType int, txHex string, txinList []CfdUtxo, utxoList []CfdUtxo, targetAmountList []CfdFundRawTxTargetAmount, option *CfdFundRawTxOption) (outputTx string, fee int64, usedAddressList []string, err error) {
	outputTx, fee, usedAddressList, _, err = CfdGoFundRawTransactionAndCalcFee(
		networkType, txHex, txinList, utxoList, targetAmountList, option)
	return
}

func CfdGoFundRawTransactionAndCalcFee(networkType int, txHex string, txinList []CfdUtxo, utxoList []CfdUtxo, targetAmountList []CfdFundRawTxTargetAmount, option *CfdFundRawTxOption) (outputTx string, fee int64, usedAddressList []string, calcFee int64, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var fundOpt CfdFundRawTxOption
	if option != nil {
		fundOpt = *option
	} else {
		fundOpt = NewCfdFundRawTxOption(networkType)
	}

	var fundHandle uintptr
	assetCount := uint32(len(targetAmountList))
	assetCountPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&assetCount)))
	ret := CfdInitializeFundRawTx(handle, networkType, assetCountPtr, fundOpt.FeeAsset, &fundHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	defer CfdFreeFundRawTxHandle(handle, fundHandle)

	for _, txin := range txinList {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txin.Vout)))
		peginBtcTxSizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txin.PeginBtcTxSize)))
		txoutproofSizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txin.PeginTxOutProofSize)))
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txin.Amount)))
		ret = CfdAddTxInputForFundRawTx(handle, fundHandle, txin.Txid, voutPtr, amountPtr, txin.Descriptor, txin.Asset, txin.IsIssuance, txin.IsBlindIssuance, txin.IsPegin, txin.ClaimScript, peginBtcTxSizePtr, txoutproofSizePtr, txin.ScriptSigTemplate)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	for _, utxo := range utxoList {
		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxo.Vout)))
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxo.Amount)))
		ret = CfdAddUtxoTemplateForFundRawTx(handle, fundHandle, utxo.Txid, voutPtr, amountPtr, utxo.Descriptor, utxo.Asset, utxo.ScriptSigTemplate)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	for idx, target := range targetAmountList {
		index := uint32(idx)
		idxPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
		amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&target.Amount)))
		ret = CfdAddTargetAmountForFundRawTx(handle, fundHandle, idxPtr, amountPtr, target.Asset, target.ReservedAddress)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
	}

	var emptyInt64 int64
	emptyInt64Ptr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&emptyInt64)))
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxIsBlind), emptyInt64Ptr, float64(0), fundOpt.IsBlindTx)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxDustFeeRate), emptyInt64Ptr, fundOpt.DustFeeRate, false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxLongTermFeeRate), emptyInt64Ptr, fundOpt.LongTermFeeRate, false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	knapsackPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&fundOpt.KnapsackMinChange)))
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxKnapsackMinChange), knapsackPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	exponentPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&fundOpt.Exponent)))
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxBlindExponent), exponentPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	minimumBitsPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&fundOpt.MinimumBits)))
	ret = CfdSetOptionFundRawTx(handle, fundHandle, int(KCfdFundTxBlindMinimumBits), minimumBitsPtr, float64(0), false)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	var appendTxoutCount uint32
	feePtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&fee)))
	appendTxoutCountPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&appendTxoutCount)))
	ret = CfdFinalizeFundRawTx(handle, fundHandle, txHex, fundOpt.EffectiveFeeRate, feePtr, appendTxoutCountPtr, &outputTx)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}

	usedAddressList = make([]string, appendTxoutCount)
	for i := uint32(0); i < appendTxoutCount; i++ {
		var addr string
		indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		ret := CfdGetAppendTxOutFundRawTx(handle, fundHandle, indexPtr, &addr)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, handle)
			return
		}
		usedAddressList[i] = addr
	}
	calcFeePtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&calcFee)))
	ret = CfdGetCalculateFeeFundRawTx(handle, fundHandle, calcFeePtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		return
	}
	return outputTx, fee, usedAddressList, calcFee, nil
}

// CfdGoGetAssetCommitment get asset commitment.
func CfdGoGetAssetCommitment(asset, assetBlinder string) (assetCommitment string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetAssetCommitment(handle, asset, assetBlinder, &assetCommitment)
	err = convertCfdError(ret, handle)
	return assetCommitment, err
}

// CfdGoGetAmountCommitment get amount commitment.
func CfdGoGetAmountCommitment(amount int64, assetCommitment, blinder string) (commitment string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdGetValueCommitment(handle, amountPtr, assetCommitment, blinder, &commitment)
	err = convertCfdError(ret, handle)
	return commitment, err
}

func CfdGoInitializeTxDataHandle(networkType int, txHex string) (txDataHandle uintptr, err error) {
	txDataHandle = uintptr(0)
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdInitializeTxDataHandle(handle, networkType, txHex, &txDataHandle)
	err = convertCfdError(ret, handle)
	return txDataHandle, err
}

func CfdGoFreeTxDataHandle(txDataHandle uintptr) (err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFreeTxDataHandle(handle, txDataHandle)
	err = convertCfdError(ret, handle)
	return
}

func CfdGoGetTxInfoByHandle(txDataHandle uintptr) (data CfdTxData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetTxInfoByHandle(handle, txDataHandle, &data.Txid, &data.Wtxid, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, handle)
	return data, err
}

func CfdGoGetConfidentialTxDataByHandle(txDataHandle uintptr) (data CfdTxData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetConfidentialTxInfoByHandle(handle, txDataHandle, &data.Txid, &data.Wtxid, &data.WitHash, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, handle)
	return data, err
}

func CfdGoGetTxInByHandle(txDataHandle uintptr, index uint32) (txid string, vout uint32, sequence uint32, scriptSig string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetTxInByHandle(handle, txDataHandle, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	err = convertCfdError(ret, handle)
	return txid, vout, sequence, scriptSig, err
}

func CfdGoGetTxInIssuanceInfoByHandle(txDataHandle uintptr, index uint32) (entropy string, nonce string, assetAmount int64, assetValue string, tokenAmount int64, tokenValue string, assetRangeproof string, tokenRangeproof string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdGetTxInIssuanceInfoByHandle(handle, txDataHandle, indexPtr, &entropy, &nonce, assetAmountPtr, &assetValue, tokenAmountPtr, &tokenValue, &assetRangeproof, &tokenRangeproof)
	err = convertCfdError(ret, handle)
	return entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err
}

func CfdGoGetTxInWitnessByHandle(txDataHandle uintptr, witnessType int, txinIndex uint32, stackIndex uint32) (stackData string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetTxInWitnessByHandle(handle, txDataHandle, witnessType, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, handle)
	return stackData, err
}

func CfdGoGetTxOutByHandle(txDataHandle uintptr, index uint32) (satoshiAmount int64, lockingScript string, asset string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetTxOutByHandle(handle, txDataHandle, indexPtr, satoshiPtr, &lockingScript, &asset)
	err = convertCfdError(ret, handle)
	return satoshiAmount, lockingScript, asset, err
}

func CfdGoGetConfidentialTxOutSimpleByHandle(txDataHandle uintptr, index uint32) (asset string, satoshiAmount int64, valueCommitment string, nonce string, lockingScript string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOutSimpleByHandle(handle, txDataHandle, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, valueCommitment, nonce, lockingScript, err
}

func CfdGoGetConfidentialTxOutByHandle(txDataHandle uintptr, index uint32) (asset string, satoshiAmount int64, valueCommitment string, nonce string, lockingScript string, surjectionProof string, rangeproof string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOutByHandle(handle, txDataHandle, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript, &surjectionProof, &rangeproof)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err
}

func CfdGoGetTxInCountByHandle(txDataHandle uintptr) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxInCountByHandle(handle, txDataHandle, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

func CfdGoGetTxInWitnessCountByHandle(txDataHandle uintptr, witnessType int, txinIndex uint32) (count uint32, err error) {
	// witnessType: 0 (normal), 1(pegin)
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxInWitnessCountByHandle(handle, txDataHandle, witnessType, txinIndexPtr, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

func CfdGoGetTxOutCountByHandle(txDataHandle uintptr) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxOutCountByHandle(handle, txDataHandle, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

func CfdGoGetTxInIndexByHandle(txDataHandle uintptr, txid string, vout uint32) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTxInIndexByHandle(handle, txDataHandle, txid, voutPtr, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

func CfdGoGetTxOutIndexByHandle(txDataHandle uintptr, address string, directLockingScript string) (index uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTxOutIndexByHandle(handle, txDataHandle, address, directLockingScript, indexPtr)
	err = convertCfdError(ret, handle)
	return index, err
}

// v0.2 API ------------------------------------------------------------------

// ByteData This struct holds a byte array.
type ByteData struct {
	hex string
}

// NewByteData This function create a bytedata from a byte array.
func NewByteData(data []byte) ByteData {
	var obj ByteData
	obj.hex = hex.EncodeToString(data)
	return obj
}

// NewByteDataFromHex This function create a bytedata from a hex string.
func NewByteDataFromHex(hexStr string) (ByteData, error) {
	var obj ByteData
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewByteDataFromHex This function create a bytedata from a hex string. On error, it returns nil.
func NewByteDataFromHexIgnoreError(hexStr string) *ByteData {
	var obj ByteData
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return nil
	}
	obj.hex = hexStr
	return &obj
}

// ToHex This function return a hex string.
func (obj *ByteData) ToHex() string {
	if obj == nil {
		return ""
	}
	return obj.hex
}

// ToHex This function return a byte array.
func (obj *ByteData) ToSlice() []byte {
	data, osErr := hex.DecodeString(obj.hex)
	if osErr != nil {
		return []byte{}
	}
	return data
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

// AdaptorSignature This struct use for the accessing to ecdsa-adaptor function.
type AdaptorSignature struct {
	Signature string
}

// NewAdaptorSignature This function return a ecdsa-adaptor's signature.
func NewAdaptorSignature(adaptorSignature ByteData) *AdaptorSignature {
	return &AdaptorSignature{Signature: adaptorSignature.hex}
}

// EncryptEcdsaAdaptor This function return a ecdsa-adaptor's signature.
func EncryptEcdsaAdaptor(msg, secretKey, encryptionKey ByteData) (adaptorSignature *AdaptorSignature, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var signature string
	ret := CfdEncryptEcdsaAdaptor(handle, msg.ToHex(), secretKey.ToHex(), encryptionKey.ToHex(), &signature)
	err = convertCfdError(ret, handle)
	if err == nil {
		adaptorSignature = &AdaptorSignature{Signature: signature}
	}
	return adaptorSignature, err
}

// Adapt This function return a decrypted signature.
func (obj *AdaptorSignature) Decrypt(adaptorSecret ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var ecSignature string
	ret := CfdDecryptEcdsaAdaptor(handle, obj.Signature, adaptorSecret.ToHex(), &ecSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: ecSignature}
	}
	return signature, err
}

// ExtractSecret This function return a adaptor secret.
func (obj *AdaptorSignature) Recover(signature, encryptionKey ByteData) (secret *ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var adaptorSecret string
	ret := CfdRecoverEcdsaAdaptor(handle, obj.Signature, signature.ToHex(), encryptionKey.ToHex(), &adaptorSecret)
	err = convertCfdError(ret, handle)
	if err == nil {
		secret = &ByteData{hex: adaptorSecret}
	}
	return secret, err
}

// Verify This function verify a ecdsa-adaptor's signature.
func (obj *AdaptorSignature) Verify(msg, pubkey, encryptionKey ByteData) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifyEcdsaAdaptor(handle, obj.Signature, msg.ToHex(), pubkey.ToHex(), encryptionKey.ToHex())
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

// SchnorrUtil This struct use for the accessing to schnorr function.
type SchnorrUtil struct {
}

// NewSchnorrUtil This function return a SchnorrUtil.
func NewSchnorrUtil() *SchnorrUtil {
	return &SchnorrUtil{}
}

// GetPubkeyFromPrivkey (deprecated) This function return a schnorr's pubkey. Please use GetSchnorrPubkeyFromPrivkey.
func (obj *SchnorrUtil) GetPubkeyFromPrivkey(key ByteData) (pubkey ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	parity := false
	ret := CfdGetSchnorrPubkeyFromPrivkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, err
}

// GetSchnorrPubkeyFromPrivkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) GetSchnorrPubkeyFromPrivkey(key ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	ret := CfdGetSchnorrPubkeyFromPrivkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, parity, err
}

// GetSchnorrPubkeyFromPubkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) GetSchnorrPubkeyFromPubkey(key ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	ret := CfdGetSchnorrPubkeyFromPubkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, parity, err
}

// TweakAddKeyPair This function return a schnorr's pubkey.
func (obj *SchnorrUtil) TweakAddKeyPair(key, tweak ByteData) (pubkey ByteData, parity bool, privkey ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var tweakedPubkey string
	var tweakedPrivkey string
	ret := CfdSchnorrKeyPairTweakAdd(handle, key.ToHex(), tweak.ToHex(), &tweakedPubkey, &parity, &tweakedPrivkey)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: tweakedPubkey}
		privkey = ByteData{hex: tweakedPrivkey}
	}
	return pubkey, parity, privkey, err
}

// TweakAddPubkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) TweakAddPubkey(key, tweak ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var tweakedPubkey string
	ret := CfdSchnorrPubkeyTweakAdd(handle, key.ToHex(), tweak.ToHex(), &tweakedPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: tweakedPubkey}
	}
	return pubkey, parity, err
}

// IsTweakedPubkey This function return a tweaked flag.
func (obj *SchnorrUtil) IsTweakedPubkey(key ByteData, parity bool, basePubkey, tweak ByteData) (isTweaked bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCheckTweakAddFromSchnorrPubkey(handle, key.ToHex(), parity, basePubkey.ToHex(), tweak.ToHex())
	if ret == (int)(KCfdSuccess) {
		isTweaked = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isTweaked = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isTweaked, err
}

// Sign This function return a schnorr's signature.
func (obj *SchnorrUtil) Sign(msg, secretKey, auxRand ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrSignature string
	ret := CfdSignSchnorr(handle, msg.ToHex(), secretKey.ToHex(), auxRand.ToHex(), &schnorrSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: schnorrSignature}
	}
	return signature, err
}

// SignWithNonce This function return a schnorr's signature with nonce.
func (obj *SchnorrUtil) SignWithNonce(msg, secretKey, nonce ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrSignature string
	ret := CfdSignSchnorrWithNonce(handle, msg.ToHex(), secretKey.ToHex(), nonce.ToHex(), &schnorrSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: schnorrSignature}
	}
	return signature, err
}

// ComputeSigPoint This function return a sig-point.
func (obj *SchnorrUtil) ComputeSigPoint(msg, nonce, pubkey ByteData) (sigPoint ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var point string
	ret := CfdComputeSchnorrSigPoint(handle, msg.ToHex(), nonce.ToHex(), pubkey.ToHex(), &point)
	err = convertCfdError(ret, handle)
	if err == nil {
		sigPoint = ByteData{hex: point}
	}
	return sigPoint, err
}

// Verify This function verify a schnorr's signature.
func (obj *SchnorrUtil) Verify(signature, msg, pubkey ByteData) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifySchnorr(handle, signature.ToHex(), msg.ToHex(), pubkey.ToHex())
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

// SplitSignature This function return schnorr nonce and schnorr privkey.
func (obj *SchnorrUtil) SplitSignature(signature ByteData) (nonce, key ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrNonce string
	var privkey string
	ret := CfdSplitSchnorrSignature(handle, signature.ToHex(), &schnorrNonce, &privkey)
	err = convertCfdError(ret, handle)
	if err == nil {
		nonce = ByteData{hex: schnorrNonce}
		key = ByteData{hex: privkey}
	}
	return nonce, key, err
}

// AddSighashTypeInSignature This function return schnorr signature added sighashType.
func (obj *SchnorrUtil) AddSighashTypeInSignature(signature *ByteData, sighashType *SigHashType) (addedSighash *ByteData, err error) {
	if signature == nil || sighashType == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var newSignature string
	ret := CfdAddSighashTypeInSchnorrSignature(handle, signature.ToHex(), sighashType.GetValue(), sighashType.AnyoneCanPay, &newSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		addedSighash = &ByteData{hex: newSignature}
	}
	return addedSighash, err
}

// v0.3 API ------------------------------------------------------------------

// Script This struct holds a script.
type Script struct {
	hex string
}

// NewScript This function create a script from a byte array.
func NewScript(data []byte) Script {
	var obj Script
	obj.hex = hex.EncodeToString(data)
	return obj
}

// NewScriptFromHex This function create a script from a hex string.
func NewScriptFromHex(hexStr string) (Script, error) {
	var obj Script
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewScriptFromHex This function create a script from a hex string. On error, it returns nil.
func NewScriptFromHexIgnoreError(hexStr string) *Script {
	var obj Script
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return nil
	}
	obj.hex = hexStr
	return &obj
}

// NewScriptFromAsm This function create a script from an asm string.
func NewScriptFromAsm(scriptAsm string) (Script, error) {
	var obj Script
	hexStr, err := CfdGoConvertScriptAsmToHex(scriptAsm)
	if err != nil {
		return obj, err
	}
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewScriptFromAsmList This function create a script from the asm string list.
func NewScriptFromAsmList(scriptAsmList []string) (Script, error) {
	var obj Script
	hexStr, err := CfdGoCreateScript(scriptAsmList)
	if err != nil {
		return obj, err
	}
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	obj.hex = hexStr
	return obj, nil
}

// ToHex This function return a hex string.
func (obj *Script) ToHex() string {
	return obj.hex
}

// ToHex This function return a byte array.
func (obj *Script) ToSlice() []byte {
	data, osErr := hex.DecodeString(obj.hex)
	if osErr != nil {
		return []byte{}
	}
	return data
}

// IsEmpty This function return a empty or not.
func (obj *Script) IsEmpty() bool {
	return len(obj.hex) == 0
}

// Parse This function return a parsing script.
func (obj *Script) Parse() (scriptItems []string, err error) {
	return CfdGoParseScript(obj.hex)
}

// Descriptor This struct use for the output descriptor.
type Descriptor struct {
	// Output Descriptor
	OutputDescriptor string
	// Network Type
	Network int
}

// NewDescriptorFromAddress This function return a Descriptor from pubkey.
func NewDescriptorFromPubkey(hashType int, pubkey string, networkType int) *Descriptor {
	var desc string
	if hashType == (int)(KCfdP2shP2wpkh) {
		desc = "sh(wpkh(" + pubkey + "))"
	} else if hashType == (int)(KCfdP2wpkh) {
		desc = "wpkh(" + pubkey + ")"
	} else {
		desc = "pkh(" + pubkey + ")"
	}
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          networkType,
	}
}

// NewDescriptorFromMultisig This function return a Descriptor from multisig.
func NewDescriptorFromMultisig(hashType int, pubkeys []string, requireNum, networkType int) *Descriptor {
	var desc string
	desc = desc + "multi(" + strconv.Itoa(requireNum) + "," + strings.Join(pubkeys, ",") + ")"
	if hashType == (int)(KCfdP2shP2wsh) {
		desc = "sh(wsh(" + desc + "))"
	} else if hashType == (int)(KCfdP2wsh) {
		desc = "wsh(" + desc + ")"
	} else if hashType == (int)(KCfdP2sh) {
		desc = "sh(" + desc + ")"
	}
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          networkType,
	}
}

// NewDescriptor This function return a Descriptor.
func NewDescriptorFromString(descriptor string, networkType int) *Descriptor {
	return &Descriptor{
		OutputDescriptor: descriptor,
		Network:          networkType,
	}
}

// NewDescriptorFromLockingScript This function return a Descriptor from locking script.
func NewDescriptorFromLockingScript(lockingScript string, networkType int) *Descriptor {
	desc := "raw(" + lockingScript + ")"
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          networkType,
	}
}

// NewDescriptorFromAddress This function return a Descriptor from address.
func NewDescriptorFromAddress(address string, networkType int) *Descriptor {
	desc := "addr(" + address + ")"
	return &Descriptor{
		OutputDescriptor: desc,
		Network:          networkType,
	}
}

// Parse This function return a Descriptor parsing data.
func (obj *Descriptor) Parse() (data CfdDescriptorData, descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, err error) {
	return CfdGoParseDescriptorData(obj.OutputDescriptor, obj.Network, "")
}

// ParseWithDerivationPath This function return a Descriptor parsing data.
func (obj *Descriptor) ParseWithDerivationPath(bip32DerivationPath string) (data CfdDescriptorData, descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, err error) {
	return CfdGoParseDescriptorData(obj.OutputDescriptor, obj.Network, bip32DerivationPath)
}

// GetChecksum This function return a descriptor adding checksum.
func (obj *Descriptor) GetChecksum() (descriptorAddedChecksum string, err error) {
	return CfdGoGetDescriptorChecksum(obj.Network, obj.OutputDescriptor)
}

// tapscript API ---------------------------------------------------------------

// CfdGoCreateScriptTreeHandle This function is create a script tree handle.
func CfdGoCreateScriptTreeHandle(handle uintptr) (treeHandle uintptr, err error) {
	ret := CfdInitializeTaprootScriptTree(handle, &treeHandle)
	err = convertCfdError(ret, handle)
	return treeHandle, err
}

// CfdGoCreateScriptTreeElementsHandle This function is create a script tree handle.
func CfdGoCreateScriptTreeElementsHandle(handle uintptr) (treeHandle uintptr, err error) {
	ret := CfdInitializeTaprootScriptTreeWithNetwork(handle, int(KCfdNetworkLiquidv1), &treeHandle)
	err = convertCfdError(ret, handle)
	return treeHandle, err
}

// CfdGoFreeScriptTreeHandle This function is free a script tree handle.
func CfdGoFreeScriptTreeHandle(handle uintptr, treeHandle uintptr) error {
	ret := CfdFreeTaprootScriptTreeHandle(handle, treeHandle)
	return convertCfdError(ret, handle)
}

// internalCreateScriptTreeHandle This function is create cfd handle and script tree handle.
func internalCreateScriptTreeHandle(networkType int) (handle uintptr, treeHandle uintptr, err error) {
	handle, err = CfdGoCreateHandle()
	if err != nil {
		return uintptr(0), uintptr(0), err
	}

	ret := CfdInitializeTaprootScriptTreeWithNetwork(handle, networkType, &treeHandle)
	err = convertCfdError(ret, handle)
	if err != nil {
		_ = CfdGoFreeHandle(handle)
		return uintptr(0), uintptr(0), err
	}
	return handle, treeHandle, err
}

// TapBranch This struct use for the taproot script tree branch.
type TapBranch struct {
	// Branch Hash
	Hash ByteData
	// TapScript
	TapScript Script
	// TapLeafHash
	TapLeafHash ByteData
	// tree string
	treeStr string
	// target node string
	targetNodeStr string
	// network type
	NetworkType int
}

// internalLoadTapBranchFromStringByNodes This function has load branch by nodes.
func internalLoadTapBranchFromStringByNodes(handle, treeHandle uintptr, treeStr string, tapscript *Script, targetNodes string, networkType int) error {
	script := ""
	node := ""
	if tapscript != nil && !tapscript.IsEmpty() {
		script = tapscript.ToHex()
		node = targetNodes
	}
	leafVersion := uint8(0xc0)
	if networkType >= int(KCfdNetworkLiquidv1) {
		leafVersion = uint8(0xc4)
	}
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	ret := CfdSetScriptTreeFromString(handle, treeHandle, treeStr, script, leafVersionPtr, node)
	return convertCfdError(ret, handle)
}

// internalGetTapBranchData This function return a TapBranch.
func internalGetTapBranchData(handle, treeHandle uintptr, treeStr string, tapscript *Script, targetNodes string, networkType int) (branch *TapBranch, err error) {
	var script, node, tapLeafHash string
	if tapscript != nil {
		script = tapscript.ToHex()
		node = targetNodes
	}

	count := uint32(0)
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTapBranchCount(handle, treeHandle, countPtr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	var hash, targetNodeStr, tempScript string
	var leafVersion uint8
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	depth := uint8(0)
	depthPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&depth)))
	ret = CfdGetBaseTapLeaf(handle, treeHandle, leafVersionPtr, &tempScript, &hash)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}
	if tapscript == nil && leafVersion != 0 {
		script = tempScript
	}
	if script != "" {
		tapLeafHash = hash
	}
	if count != uint32(0) { // top branch
		// index := uint8(0)
		index := uint8(count) - 1
		indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
		ret = CfdGetTapBranchData(handle, treeHandle, indexPtr, true, &hash, leafVersionPtr, &tempScript, depthPtr)
		if err = convertCfdError(ret, handle); err != nil {
			return nil, err
		}
	}

	if node != "" {
		targetNodeStr = node
	} else if len(script) != 0 {
		for idx := uint8(0); idx < uint8(count); idx++ {
			var branchHash string
			idxPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&idx)))
			ret = CfdGetTapBranchData(handle, treeHandle, idxPtr, false, &branchHash, leafVersionPtr, &tempScript, depthPtr)
			if err = convertCfdError(ret, handle); err != nil {
				return nil, err
			}
			targetNodeStr += branchHash
		}
	}

	branch = &TapBranch{
		Hash:          ByteData{hex: hash},
		TapScript:     Script{hex: script},
		TapLeafHash:   ByteData{hex: tapLeafHash},
		treeStr:       treeStr,
		targetNodeStr: targetNodeStr,
		NetworkType:   networkType,
	}
	return branch, nil
}

// NewTapBranchFromHash This function return a TapBranch.
func NewTapBranchFromHash(hash *ByteData) (*TapBranch, error) {
	return NewTapBranchFromHashWithNetwork(hash, int(KCfdNetworkMainnet))
}

// NewTapBranchFromHashWithNetwork This function return a TapBranch.
func NewTapBranchFromHashWithNetwork(hash *ByteData, networkType int) (*TapBranch, error) {
	if hash == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	if len(hash.hex) != 64 {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	emptyScript := Script{hex: ""}
	treeStr := hash.ToHex()
	return &TapBranch{
		Hash:          *hash,
		TapScript:     emptyScript,
		TapLeafHash:   ByteData{},
		treeStr:       treeStr,
		targetNodeStr: "",
		NetworkType:   networkType,
	}, nil
}

// NewTapBranchFromTapScript This function return a TapBranch from tapscript.
func NewTapBranchFromTapScript(tapscript *Script) (*TapBranch, error) {
	return NewTapBranchFromTapScriptWithNetwork(tapscript, int(KCfdNetworkMainnet))
}

// NewElementsTapBranchFromTapScript This function return a TapBranch from tapscript.
func NewElementsTapBranchFromTapScript(tapscript *Script) (*TapBranch, error) {
	return NewTapBranchFromTapScriptWithNetwork(tapscript, int(KCfdNetworkLiquidv1))
}

// NewTapBranchFromTapScriptWithNetwork This function return a TapBranch from tapscript.
func NewTapBranchFromTapScriptWithNetwork(tapscript *Script, networkType int) (*TapBranch, error) {
	if tapscript == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle(networkType)
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	leafVersion := uint8(0xc0)
	if networkType >= int(KCfdNetworkLiquidv1) {
		leafVersion = uint8(0xc4)
	}
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	ret := CfdSetInitialTapLeaf(handle, treeHandle, tapscript.ToHex(), leafVersionPtr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	var treeStr string
	ret = CfdGetTaprootScriptTreeString(handle, treeHandle, &treeStr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, treeStr, tapscript, "", networkType)
	return branch, err
}

// NewTapBranchFromString This function return a TapBranch from tree string.
func NewTapBranchFromString(treeStr string, tapscript *Script) (*TapBranch, error) {
	branch, err := NewTapBranchFromStringByNodes(treeStr, tapscript, []string{})
	return branch, err
}

// NewElementsTapBranchFromString This function return a TapBranch from tree string.
func NewElementsTapBranchFromString(treeStr string, tapscript *Script) (*TapBranch, error) {
	branch, err := NewElementsTapBranchFromStringByNodes(treeStr, tapscript, []string{})
	return branch, err
}

// NewTapBranchFromStringByNodesWithNetwork This function return a TapBranch from tree string.
func NewTapBranchFromStringWithNetwork(treeStr string, tapscript *Script, networkType int) (*TapBranch, error) {
	branch, err := NewTapBranchFromStringByNodesWithNetwork(treeStr, tapscript, []string{}, networkType)
	return branch, err
}

// NewTapBranchFromStringByNodes This function return a TapBranch from tree string and nodes.
func NewTapBranchFromStringByNodes(treeStr string, tapscript *Script, nodes []string) (*TapBranch, error) {
	return internalNewTapBranchFromStringByNodes(treeStr, tapscript, nodes, int(KCfdNetworkMainnet))
}

// NewElementsTapBranchFromStringByNodes This function return a TapBranch from tree string and nodes.
func NewElementsTapBranchFromStringByNodes(treeStr string, tapscript *Script, nodes []string) (*TapBranch, error) {
	return internalNewTapBranchFromStringByNodes(treeStr, tapscript, nodes, int(KCfdNetworkLiquidv1))
}

// NewTapBranchFromStringByNodesWithNetwork This function return a TapBranch from tree string and nodes.
func NewTapBranchFromStringByNodesWithNetwork(treeStr string, tapscript *Script, nodes []string, networkType int) (*TapBranch, error) {
	return internalNewTapBranchFromStringByNodes(treeStr, tapscript, nodes, networkType)
}

// internalNewTapBranchFromStringByNodes This function return a TapBranch from tree string and nodes.
func internalNewTapBranchFromStringByNodes(treeStr string, tapscript *Script, nodes []string, networkType int) (*TapBranch, error) {
	targetNodes := ""
	if tapscript != nil && len(nodes) > 0 {
		targetNodes = strings.Join(nodes, "")
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle(networkType)
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, treeStr, tapscript, targetNodes, networkType)
	if err != nil {
		return nil, err
	}

	var newTreeStr string
	ret := CfdGetTaprootScriptTreeString(handle, treeHandle, &newTreeStr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	return internalGetTapBranchData(handle, treeHandle, newTreeStr, tapscript, targetNodes, networkType)
}

// NewTapBranchFromControlBlock This function return a TapBranch from control block.
func NewTapBranchFromControlBlock(controlBlock *ByteData, tapscript *Script) (branch *TapBranch, internalPubkey *ByteData, err error) {
	return NewTapBranchFromControlBlockWithNetwork(controlBlock, tapscript, int(KCfdNetworkMainnet))
}

// NewElementsTapBranchFromControlBlock This function return a TapBranch from control block.
func NewElementsTapBranchFromControlBlock(controlBlock *ByteData, tapscript *Script) (branch *TapBranch, internalPubkey *ByteData, err error) {
	return NewTapBranchFromControlBlockWithNetwork(controlBlock, tapscript, int(KCfdNetworkLiquidv1))
}

// NewTapBranchFromControlBlockWithNetwork This function return a TapBranch from control block.
func NewTapBranchFromControlBlockWithNetwork(controlBlock *ByteData, tapscript *Script, networkType int) (branch *TapBranch, internalPubkey *ByteData, err error) {
	if controlBlock == nil || tapscript == nil {
		return nil, nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}

	handle, treeHandle, err := internalCreateScriptTreeHandle(networkType)
	if err != nil {
		return nil, nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	internalPubkeyStr := ""
	ret := CfdSetTapScriptByWitnessStack(handle, treeHandle, controlBlock.ToHex(), tapscript.ToHex(), &internalPubkeyStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, err
	}

	var tempScript string
	var hash string
	var leafVersion uint8
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	index := uint8(0)
	indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
	depth := uint8(0)
	depthPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&depth)))
	ret = CfdGetTapBranchData(handle, treeHandle, indexPtr, true, &hash, leafVersionPtr, &tempScript, depthPtr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, err
	}

	var treeStr string
	ret = CfdGetTaprootScriptTreeString(handle, treeHandle, &treeStr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, nil, err
	}

	branch, err = internalGetTapBranchData(handle, treeHandle, treeStr, tapscript, "", networkType)
	if err != nil {
		return nil, nil, err
	}

	internalPubkey = &ByteData{hex: internalPubkeyStr}
	return branch, internalPubkey, nil
}

// GetTreeString This function return a tapbranch tree string.
func (obj *TapBranch) GetTreeString() string {
	return obj.treeStr
}

// AddBranchByTapScript This function is adding a tapscript.
func (obj *TapBranch) AddBranchByTapScript(tapscript *Script) error {
	if tapscript == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return err
	}

	leafVersion := uint8(0xc0)
	if obj.NetworkType >= int(KCfdNetworkLiquidv1) {
		leafVersion = uint8(0xc4)
	}
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	ret := CfdAddTapBranchByTapLeaf(handle, treeHandle, tapscript.ToHex(), leafVersionPtr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	regBr, err := NewTapBranchFromTapScriptWithNetwork(tapscript, obj.NetworkType)
	if err != nil {
		return err
	}

	var newTreeStr string
	ret = CfdGetTaprootScriptTreeString(handle, treeHandle, &newTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, newTreeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err == nil {
		obj.Hash = branch.Hash
		obj.treeStr = newTreeStr
		obj.targetNodeStr = obj.targetNodeStr + regBr.Hash.ToHex()
	}
	return err
}

// AddBranchByHash This function is adding a tapbranch hash.
func (obj *TapBranch) AddBranchByHash(hash *ByteData) error {
	if hash == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}

	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return err
	}

	ret := CfdAddTapBranchByHash(handle, treeHandle, hash.hex)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	var newTreeStr string
	ret = CfdGetTaprootScriptTreeString(handle, treeHandle, &newTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, newTreeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err == nil {
		obj.Hash = branch.Hash
		obj.treeStr = newTreeStr
		obj.targetNodeStr = obj.targetNodeStr + hash.hex
	}
	return err
}

// AddBranchByBranch This function is adding a tapbranch.
func (obj *TapBranch) AddBranchByBranch(branch *TapBranch) error {
	if branch == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	return obj.AddBranchByString(branch.treeStr)
}

// AddBranchByString This function return a tapbranch string.
func (obj *TapBranch) AddBranchByString(treeStr string) error {
	addBranch, err := NewTapBranchFromStringWithNetwork(treeStr, nil, obj.NetworkType)
	if err != nil {
		return err
	}

	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return err
	}

	ret := CfdAddTapBranchByScriptTreeString(handle, treeHandle, treeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	var newTreeStr string
	ret = CfdGetTaprootScriptTreeString(handle, treeHandle, &newTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, newTreeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err == nil {
		obj.Hash = branch.Hash
		obj.treeStr = newTreeStr
		obj.targetNodeStr = obj.targetNodeStr + addBranch.Hash.ToHex()
	}
	return err
}

// GetMaxBranchCount This function return a branch count.
func (obj *TapBranch) GetMaxBranchCount() (count uint32, err error) {
	count = uint32(0)
	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return
	}

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTapBranchCount(handle, treeHandle, countPtr)
	err = convertCfdError(ret, handle)
	return
}

// GetBranch This function return a tapbranch.
func (obj *TapBranch) GetBranch(index uint8) (branch *TapBranch, err error) {
	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return
	}

	var branchHandle uintptr
	var hash string
	indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTapBranchHandle(handle, treeHandle, indexPtr, &hash, &branchHandle)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}
	defer CfdGoFreeScriptTreeHandle(handle, branchHandle)

	var branchTreeStr string
	ret = CfdGetTaprootScriptTreeString(handle, branchHandle, &branchTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}

	return internalGetTapBranchData(handle, branchHandle, branchTreeStr, nil, "", obj.NetworkType)
}

// GetControlNodeList This function return control node list.
func (obj *TapBranch) GetControlNodeList() (nodeList []string, err error) {
	nodeList = []string{}
	/*
		if obj.TapScript.IsEmpty() {
			return nodeList, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
		}
	*/
	if obj.TapScript.IsEmpty() {
		return nodeList, nil
	}
	if len(obj.targetNodeStr) == 0 {
		return nodeList, nil
	}
	if (len(obj.targetNodeStr) % 64) != 0 {
		return nodeList, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
	}
	offset := 0
	endOffset := 0
	count := len(obj.targetNodeStr) / 64
	nodeList = make([]string, count)
	for index := 0; index < count; index++ {
		offset = 64 * index
		endOffset = offset + 64
		nodeList[index] = obj.targetNodeStr[offset:endOffset]
	}
	return nodeList, nil
}

// GetTweakedPubkey This function return a tweaked pubkey by tapscript tree.
func (obj *TapBranch) GetTweakedPubkey(internalPubkey *ByteData) (pubkey *ByteData, tapLeafHash *ByteData, controlBlock *ByteData, err error) {
	if internalPubkey == nil {
		return nil, nil, nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	/*
		if obj.TapScript.IsEmpty() {
			return nil, nil, nil, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
		}
	*/
	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return nil, nil, nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return nil, nil, nil, err
	}

	var branchHash string
	var tapLeafHashStr string
	var controlBlockStr string
	ret := CfdGetTaprootScriptTreeHash(handle, treeHandle, internalPubkey.ToHex(), &branchHash, &tapLeafHashStr, &controlBlockStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, nil, err
	}

	return &ByteData{hex: branchHash}, &ByteData{hex: tapLeafHashStr}, &ByteData{hex: controlBlockStr}, nil
}

// GetTweakedPrivkey This function return a tweaked privkey by tapscript tree.
func (obj *TapBranch) GetTweakedPrivkey(internalPrivkey *ByteData) (privkey *ByteData, err error) {
	if internalPrivkey == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	/*
		if obj.TapScript.IsEmpty() {
			return nil, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
		}
	*/
	handle, treeHandle, err := internalCreateScriptTreeHandle(obj.NetworkType)
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr, obj.NetworkType)
	if err != nil {
		return nil, err
	}

	var privkeyStr string
	ret := CfdGetTaprootTweakedPrivkey(handle, treeHandle, internalPrivkey.ToHex(), &privkeyStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}

	return &ByteData{hex: privkeyStr}, nil
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

// SetElementsUtxoListByHandle This function has adding utxo list.
func SetElementsUtxoListByHandle(createTxHandle uintptr, txinUtxoList []CfdUtxo) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	isAlreadySetGenesisBlockHash := false
	for _, utxo := range txinUtxoList {
		if !isAlreadySetGenesisBlockHash && utxo.GenesisBlockHash != "" {
			ret := CfdSetConfidentialTxGenesisBlockHashByHandle(handle, createTxHandle, utxo.GenesisBlockHash)
			if err = convertCfdError(ret, handle); err != nil {
				return err
			}
			isAlreadySetGenesisBlockHash = true
		}

		voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxo.Vout)))
		satoshiAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxo.Amount)))
		ret := CfdSetConfidentialTxUtxoDataByHandle(handle, createTxHandle, utxo.Txid, voutPtr, satoshiAmountPtr, utxo.AmountCommitment, utxo.Descriptor, "", utxo.Asset, utxo.AssetCommitment, utxo.AmountBlinder, utxo.AssetBlinder, utxo.ScriptSigTemplate, false)
		if err = convertCfdError(ret, handle); err != nil {
			return err
		}
	}

	return nil
}

// SetConfidentialTxGenesisBlockHashByHandle set the genesis block hash for tx handle.
func SetConfidentialTxGenesisBlockHashByHandle(createTxHandle uintptr, genesisBlockHash string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdSetConfidentialTxGenesisBlockHashByHandle(handle, createTxHandle, genesisBlockHash)
	return convertCfdError(ret, handle)
}

// CfdGoAddTxSignWithPrivkeyByUtxoList This function add sign with prikey.
func CfdGoAddTxSignWithPrivkeyByUtxoList(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32, privkey string, sighashType *SigHashType, hasGrindR bool, auxRand, annex *ByteData) (outputTxHex string, err error) {
	outputTxHex = ""
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if networkType >= int(KCfdNetworkLiquidv1) {
		if err = SetElementsUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	} else {
		if err = SetUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	}

	if err = SignWithPrivkeyByHandle(txHandle, txid, vout, privkey, sighashType, hasGrindR, auxRand, annex); err != nil {
		return
	}
	return internalFinalizeTransaction(txHandle)
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

// CfdGoGetSighash This function return a sighash.
func CfdGoGetSighash(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32, sighashType *SigHashType, pubkey *ByteData, redeemScript *Script, tapLeafHash, annex *ByteData, codeSeparatorPosition *uint32) (sighash string, err error) {
	sighash = ""
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if networkType >= int(KCfdNetworkLiquidv1) {
		if err = SetElementsUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	} else {
		if err = SetUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	}
	// TODO: Maybe it should be compensated on the part of the native library.
	if redeemScript != nil && len(redeemScript.ToHex()) > 0 && tapLeafHash == nil {
		branch, err := NewTapBranchFromTapScriptWithNetwork(redeemScript, networkType)
		if err != nil {
			return "", err
		}
		tapLeafHash = &branch.TapLeafHash
	}

	return GetSighash(txHandle, txid, vout, sighashType, pubkey, redeemScript, tapLeafHash, annex, codeSeparatorPosition)
}

// CfdGoGetSighashByKey This function return a sighash by pubkey.
func CfdGoGetSighashByKey(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32, sighashType *SigHashType, pubkey *ByteData, annex *ByteData) (sighash string, err error) {
	return CfdGoGetSighash(networkType, txHex, txinUtxoList, txid, vout, sighashType, pubkey, nil, nil, annex, nil)
}

// CfdGoGetSighashByScript This function return a sighash by redeem script.
func CfdGoGetSighashByScript(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32, sighashType *SigHashType, redeemScript *Script) (sighash string, err error) {
	return CfdGoGetSighash(networkType, txHex, txinUtxoList, txid, vout, sighashType, nil, redeemScript, nil, nil, nil)
}

// CfdGoGetSighashByTapScript This function return a sighash by tapscript.
func CfdGoGetSighashByTapScript(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32, sighashType *SigHashType, redeemScript *Script, tapLeafHash, annex *ByteData, codeSeparatorPosition *uint32) (sighash string, err error) {
	return CfdGoGetSighash(networkType, txHex, txinUtxoList, txid, vout, sighashType, nil, redeemScript, tapLeafHash, annex, codeSeparatorPosition)
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

// CfdGoVerifySign This function return a verify sign results.
func CfdGoVerifySign(networkType int, txHex string, txinUtxoList []CfdUtxo, txid string, vout uint32) (isVerify bool, reason string, err error) {
	isVerify = false
	reason = ""
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if networkType >= int(KCfdNetworkLiquidv1) {
		if err = SetElementsUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	} else {
		if err = SetUtxoListByHandle(txHandle, txinUtxoList); err != nil {
			return
		}
	}
	return VerifySign(txHandle, txid, vout)
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

// CfdGoAddTaprootSchnorrSign This function add a taproot schnorr sign.
func CfdGoAddTaprootSchnorrSign(networkType int, txHex string, txid string, vout uint32, signature *ByteData, annex *ByteData) (outputTxHex string, err error) {
	outputTxHex = ""
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = AddTaprootSchnorrSign(txHandle, txid, vout, signature, annex); err != nil {
		return
	}
	return internalFinalizeTransaction(txHandle)
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

// CfdGoAddTapScriptSign This function add a tapscript sign.
func CfdGoAddTapScriptSign(networkType int, txHex string, txid string, vout uint32, signDataList []ByteData, tapscript *Script, controlBlock *ByteData, annex *ByteData) (outputTxHex string, err error) {
	outputTxHex = ""
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = AddTapScriptSign(txHandle, txid, vout, signDataList, tapscript, controlBlock, annex); err != nil {
		return
	}
	return internalFinalizeTransaction(txHandle)
}

// TxOut : transaction output.
type CfdTxOut struct {
	// satoshi amount.
	Amount int64
	// locking script.
	LockingScript string
	// address (if locking script is usual hashtype.)
	Address string
}

// ConfidentialTxOut : confidential transaction output.
type CfdConfidentialTxOut struct {
	// satoshi amount (unblind value)
	Amount int64
	// asset (or commitment asset)
	Asset string
	// locking script
	LockingScript string
	// address or confidential address. (if locking script is usual hashtype.)
	Address string
	// commitment value
	CommitmentValue string
	// commitment nonce
	CommitmentNonce string
	// surjectionprooof of asset
	Surjectionproof string
	// rangeproof of value
	Rangeproof string
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

// CfdGoSplitTxOut This function set the split outputs.
func CfdGoSplitTxOut(txHex string, index uint32, txouts []CfdTxOut) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkMainnet), txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = SplitTxOut(txHandle, index, txouts); err != nil {
		return "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", err
	}
	return outputTxHex, err
}

// CfdGoSplitConfidentialTxOut This function set the split outputs.
func CfdGoSplitConfidentialTxOut(txHex string, index uint32, txouts []CfdConfidentialTxOut) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkLiquidv1), txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = SplitConfidentialTxOut(txHandle, index, txouts); err != nil {
		return "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", err
	}
	return outputTxHex, err
}

// CfdGoGetTxOutIndexes This function get txout index list.
func CfdGoGetTxOutIndexes(networkType int, txHex string, address, directLockingScript string) (indexes []uint32, err error) {
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return indexes, err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)
	return GetTxOutIndexes(txHandle, address, directLockingScript)
}

// GetPeginAddress This function get a pegin address.
func GetPeginAddress(mainchainNetworkType int, fedpegScript string, hashType int, pubkey, redeemScript string) (peginAddress, claimScript, tweakedFedpegScript string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetPeginAddress(handle, mainchainNetworkType, fedpegScript,
		hashType, pubkey, redeemScript, &peginAddress, &claimScript, &tweakedFedpegScript)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoGetPeginAddress This function get a pegin address.
func CfdGoGetPeginAddress(mainchainNetworkType int, fedpegScript string, hashType int, pubkey, redeemScript string) (peginAddress, claimScript, tweakedFedpegScript string, err error) {
	return GetPeginAddress(mainchainNetworkType, fedpegScript, hashType, pubkey, redeemScript)
}

// GetPegoutAddress This function get a pegout address.
func GetPegoutAddress(mainchainNetworkType, elementsNetworkType int, descriptorOrXpub string, bip32Counter uint32, addressType int) (pegoutAddress, baseDescriptor string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	bip32CounterPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&bip32Counter)))
	ret := CfdGetPegoutAddress(handle, mainchainNetworkType, elementsNetworkType, descriptorOrXpub, bip32CounterPtr, addressType, &pegoutAddress, &baseDescriptor)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoGetPegoutAddress This function get a pegout address.
func CfdGoGetPegoutAddress(mainchainNetworkType, elementsNetworkType int, descriptorOrXpub string, bip32Counter uint32, addressType int) (pegoutAddress, baseDescriptor string, err error) {
	return GetPegoutAddress(mainchainNetworkType, elementsNetworkType, descriptorOrXpub, bip32Counter, addressType)
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

// CfdGoAddPeginInput This function add a pegin input.
func CfdGoAddPeginInput(txHex string, txid string, vout uint32, amount int64, asset, mainchainGenesisBlockHash, claimScript, mainchainTxHex, txoutProof string) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkLiquidv1), txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = AddPeginInput(txHandle, txid, vout, amount, asset, mainchainGenesisBlockHash, claimScript, mainchainTxHex, txoutProof); err != nil {
		return "", err
	}
	if outputTxHex, err = internalFinalizeTransaction(txHandle); err != nil {
		return "", err
	}
	return outputTxHex, err
}

// CfdGoAddPegoutOutput This function add a pegout output.
func CfdGoAddPegoutOutput(txHex string, asset string, amount int64, mainchainNetworkType, elementsNetworkType int, mainchainGenesisBlockHash, onlinePubkey, masterOnlineKey, mainchainOutputDescriptor string, bip32Counter uint32, whitelist string) (outputTxHex string, mainchainAddress string, err error) {
	txHandle, err := internalInitializeTransactionByHex(elementsNetworkType, txHex)
	if err != nil {
		return "", "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if mainchainAddress, err = AddPegoutOutput(txHandle, asset, amount, mainchainNetworkType, elementsNetworkType, mainchainGenesisBlockHash, onlinePubkey, masterOnlineKey, mainchainOutputDescriptor, bip32Counter, whitelist); err != nil {
		return "", "", err
	}

	if outputTxHex, err = internalFinalizeTransaction(txHandle); err != nil {
		return "", "", err
	}
	return outputTxHex, mainchainAddress, err
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

// CfdGoGetPegoutAddressFromTransaction This function get a pegout address from transaction.
func CfdGoGetPegoutAddressFromTransaction(networkType int, txHex string, index uint32, mainchainNetwork int) (pegoutAddress string, isPegoutOutput bool, err error) {
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return "", false, err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	isPegoutOutput, err = HasPegoutOutput(txHandle, index)
	if err != nil {
		return "", false, err
	} else if !isPegoutOutput {
		return "", false, nil
	}
	pegoutAddress, err = GetPegoutAddressFromTransaction(txHandle, index, mainchainNetwork)
	return pegoutAddress, true, err
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

// CfdGoUpdateTxInSequence This function set a sequence number.
func CfdGoUpdateTxInSequence(networkType int, txHex string, txid string, vout uint32, sequence uint32) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = UpdateTxInSequence(txHandle, txid, vout, sequence); err != nil {
		return "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", err
	}
	return outputTxHex, err
}

// CfdGoUpdateWitnessStack This function set a witness stack item.
func CfdGoUpdateWitnessStack(networkType int, txHex string, txid string, vout uint32, witnessIndex uint32, data string) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex(networkType, txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = UpdateWitnessStack(txHandle, txid, vout, witnessIndex, data); err != nil {
		return "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", err
	}
	return outputTxHex, err
}

// CfdGoUpdatePeginWitnessStack This function set a witness stack item
func CfdGoUpdatePeginWitnessStack(txHex string, txid string, vout uint32, witnessIndex uint32, data string) (outputTxHex string, err error) {
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkLiquidv1), txHex)
	if err != nil {
		return "", err
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	if err = UpdatePeginWitnessStack(txHandle, txid, vout, witnessIndex, data); err != nil {
		return "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", err
	}
	return outputTxHex, err
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

// CfdGoSetRawIssueAsset This function set a issuance information.
func CfdGoSetRawIssueAsset(txHex string, txid string, vout uint32, contractHash string, assetSatoshiAmount int64, assetAddress, assetLockingScript string, tokenSatoshiAmount int64, tokenAddress, tokenLockingScript string, isBlindAsset bool) (entropy, asset, token, outputTxHex string, err error) {
	outputTxHex = ""
	txHandle, err := internalInitializeTransactionByHex((int)(KCfdNetworkLiquidv1), txHex)
	if err != nil {
		return
	}
	defer CfdFreeTransactionHandle(uintptr(0), txHandle)

	entropy, asset, token, err = SetIssueAsset(txHandle, txid, vout, contractHash, assetSatoshiAmount, assetAddress, assetLockingScript, tokenSatoshiAmount, tokenAddress, tokenLockingScript, isBlindAsset)
	if err != nil {
		return "", "", "", "", err
	}
	outputTxHex, err = internalFinalizeTransaction(txHandle)
	if err != nil {
		return "", "", "", "", err
	}
	return entropy, asset, token, outputTxHex, err
}

// BlockHeader block header information.
type BlockHeader struct {
	Version       uint32 // Version
	PrevBlockHash string // previous block hash
	MerkleRoot    string // merkleroot
	Time          uint32 // block time
	Bits          uint32 // bit flag
	Nonce         uint32 // nonce
}

// InitializeTransactionByHex This function is open block handle.
func InitializeBlockHandleByHex(networkType int, block string) (blockHandle uintptr, err error) {
	blockHandle = uintptr(0)
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdInitializeBlockHandle(handle, networkType, block, &blockHandle)
	err = convertCfdError(ret, handle)
	return blockHandle, err
}

// FreeBlockHandle This function is free block handle.
func FreeBlockHandle(blockHandle uintptr) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdFreeBlockHandle(handle, blockHandle)
	return convertCfdError(ret, handle)
}

// GetBlockHash This function get a block hash.
func GetBlockHash(blockHandle uintptr) (blockHash string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetBlockHash(handle, blockHandle, &blockHash)
	err = convertCfdError(ret, handle)
	return blockHash, err
}

// GetBlockHeaderData This function get a block header data.
func GetBlockHeaderData(blockHandle uintptr) (header *BlockHeader, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	blockHeader := BlockHeader{}
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&blockHeader.Version)))
	timePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&blockHeader.Time)))
	bitsPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&blockHeader.Bits)))
	noncePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&blockHeader.Nonce)))
	ret := CfdGetBlockHeaderData(handle, blockHandle, versionPtr, &blockHeader.PrevBlockHash, &blockHeader.MerkleRoot, timePtr, bitsPtr, noncePtr)
	err = convertCfdError(ret, handle)
	header = &blockHeader
	return header, err
}

// GetTransactionFromBlock This function get a transaction data.
func GetTransactionFromBlock(blockHandle uintptr, txid string) (txHex string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetTransactionFromBlock(handle, blockHandle, txid, &txHex)
	err = convertCfdError(ret, handle)
	return txHex, err
}

// GetTxOutProof This function get a txoutproof.
func GetTxOutProof(blockHandle uintptr, txid string) (txoutProof string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdGetTxOutProof(handle, blockHandle, txid, &txoutProof)
	err = convertCfdError(ret, handle)
	return txoutProof, err
}

// ExistTxidInBlock This function get a exist tx in a block.
func ExistTxidInBlock(blockHandle uintptr, txid string) (exist bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdExistTxidInBlock(handle, blockHandle, txid)
	if ret == int(KCfdSuccess) {
		exist = true
	} else {
		exist = false
		if ret != int(KCfdNotFoundError) {
			err = convertCfdError(ret, handle)
		}
	}
	return exist, err
}

// GetTxCountInBlock This function get a transaction count in this block.
func GetTxCountInBlock(blockHandle uintptr) (count uint32, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTxCountInBlock(handle, blockHandle, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

// GetTxidFromBlock This function get a txid from block.
func GetTxidFromBlock(blockHandle uintptr, offset uint32) (txid string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	offsetPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&offset)))
	ret := CfdGetTxidFromBlock(handle, blockHandle, offsetPtr, &txid)
	err = convertCfdError(ret, handle)
	return txid, err
}

// GetTxidListFromBlock This function get txid list from block.
func GetTxidListFromBlock(blockHandle uintptr) (txidList []string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	count, err := GetTxCountInBlock(blockHandle)
	if err != nil {
		return nil, err
	}
	txidList = make([]string, count)

	for index := uint32(0); index < count; index++ {
		indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
		ret := CfdGetTxidFromBlock(handle, blockHandle, indexPtr, &txidList[index])
		err = convertCfdError(ret, handle)
		if err != nil {
			return nil, err
		}
	}
	return txidList, err
}

// CfdGoGetBlockHeaderData This function get a block header data.
func CfdGoGetBlockHeaderData(networkType int, block string) (blockHash string, header *BlockHeader, err error) {
	blockHash = ""
	blockHandle, err := InitializeBlockHandleByHex(networkType, block)
	if err != nil {
		return
	}
	defer CfdFreeBlockHandle(uintptr(0), blockHandle)

	blockHash, err = GetBlockHash(blockHandle)
	if err != nil {
		return "", nil, err
	}
	header, err = GetBlockHeaderData(blockHandle)
	if err != nil {
		return "", nil, err
	}
	return blockHash, header, err
}

// CfdGoGetTxCountInBlock This function get a tx count.
func CfdGoGetTxCountInBlock(networkType int, block string) (count uint32, err error) {
	blockHandle, err := InitializeBlockHandleByHex(networkType, block)
	if err != nil {
		return
	}
	defer CfdFreeBlockHandle(uintptr(0), blockHandle)

	return GetTxCountInBlock(blockHandle)
}

// CfdGoGetTxidListFromBlock This function get txid list from block.
func CfdGoGetTxidListFromBlock(networkType int, block string) (txidList []string, err error) {
	blockHandle, err := InitializeBlockHandleByHex(networkType, block)
	if err != nil {
		return
	}
	defer CfdFreeBlockHandle(uintptr(0), blockHandle)

	return GetTxidListFromBlock(blockHandle)
}

// CfdGoGetTransactionDataFromBlock This function get a tx data.
func CfdGoGetTransactionDataFromBlock(networkType int, block, txid string) (txHex, txoutProof string, err error) {
	blockHandle, err := InitializeBlockHandleByHex(networkType, block)
	if err != nil {
		return
	}
	defer CfdFreeBlockHandle(uintptr(0), blockHandle)

	txHex, err = GetTransactionFromBlock(blockHandle, txid)
	if err != nil {
		return "", "", err
	}

	txoutProof, err = GetTxOutProof(blockHandle, txid)
	if err != nil {
		return "", "", err
	}
	return txHex, txoutProof, err
}

// CfdGoExistTxidInBlock This function get a exist tx in a block.
func CfdGoExistTxidInBlock(networkType int, block, txid string) (exist bool, err error) {
	blockHandle, err := InitializeBlockHandleByHex(networkType, block)
	if err != nil {
		return
	}
	defer CfdFreeBlockHandle(uintptr(0), blockHandle)

	return ExistTxidInBlock(blockHandle, txid)
}

// CfdGoUnblindData This function returns unblind txout data.
func CfdGoUnblindData(blindingKey, lockingScript, assetCommitment, valueCommitment, commitmentNonce, rangeproof string) (amount int64, asset, assetBlindFactor, valueBlindFactor string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	amountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
	ret := CfdUnblindTxOutData(handle, blindingKey, lockingScript, assetCommitment, valueCommitment, commitmentNonce, rangeproof, &asset, amountPtr, &assetBlindFactor, &valueBlindFactor)
	err = convertCfdError(ret, handle)
	if err != nil {
		return 0, "", "", "", err
	}
	return amount, asset, assetBlindFactor, valueBlindFactor, nil
}

// CfdGoEncryptAES ...
func CfdGoEncryptAES(key, cbcIv, buffer string) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdEncryptAES(handle, key, cbcIv, buffer, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoDecryptAES ...
func CfdGoDecryptAES(key, cbcIv, buffer string) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdDecryptAES(handle, key, cbcIv, buffer, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoEncodeBase64 ...
func CfdGoEncodeBase64(buffer string) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdEncodeBase64(handle, buffer, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoDecodeBase64 ...
func CfdGoDecodeBase64(base64 string) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdDecodeBase64(handle, base64, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoEncodeBase58 ...
func CfdGoEncodeBase58(buffer string, useChecksum bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdEncodeBase58(handle, buffer, useChecksum, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoDecodeBase58 ...
func CfdGoDecodeBase58(base58 string, useChecksum bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdDecodeBase58(handle, base58, useChecksum, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoRipemd160 ...
func CfdGoRipemd160(message string, hasText bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdRipemd160(handle, message, hasText, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoSha256 ...
func CfdGoSha256(message string, hasText bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdSha256(handle, message, hasText, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoHash160 ...
func CfdGoHash160(message string, hasText bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdHash160(handle, message, hasText, &output)
	err = convertCfdError(ret, handle)
	return
}

// CfdGoHash256 ...
func CfdGoHash256(message string, hasText bool) (output string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdHash256(handle, message, hasText, &output)
	err = convertCfdError(ret, handle)
	return
}

// custom prefix API -----------------------------------------------------------

// CfdGoSetCustomPrefix set custom prefix by json.
func CfdGoSetCustomPrefix(jsonStr string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	var respStr string
	ret := CfdRequestExecuteJson(handle, "SetCustomPrefix", jsonStr, &respStr)
	err = convertCfdError(ret, handle)
	return err
}

// CfdGoClearCustomPrefix clear custom prefix.
func CfdGoClearCustomPrefix() error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	var respStr string
	ret := CfdRequestExecuteJson(handle, "ClearCustomPrefix", "", &respStr)
	err = convertCfdError(ret, handle)
	return err
}

const (
	ExtkeyFormatTypeBip32 int = 0
	ExtkeyFormatTypeBip49 int = 1
	ExtkeyFormatTypeBip84 int = 2
)

// CfdGoCreateExtkeyByFormat create extended key by format.
func CfdGoCreateExtkeyByFormat(networkType int, extkeyType int, fingerprint string, key string, chainCode string, depth byte, childNumber uint32, formatType int) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	childNumberPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childNumber)))
	ret := CfdCreateExtkeyByFormat(handle, networkType, extkeyType, "", fingerprint, key, chainCode, depth, childNumberPtr, formatType, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

// CfdGoCreateExtkeyByFormatFromParent create extended key by format.
func CfdGoCreateExtkeyByFormatFromParent(networkType int, extkeyType int, parentKey string, key string, chainCode string, depth byte, childNumber uint32, formatType int) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	childNumberPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childNumber)))
	ret := CfdCreateExtkeyByFormat(handle, networkType, extkeyType, parentKey, "", key, chainCode, depth, childNumberPtr, formatType, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

// CfdGoCreateExtkeyByFormatFromSeed create extended key by format.
func CfdGoCreateExtkeyByFormatFromSeed(seed string, networkType int, keyType int, formatType int) (extkey string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCreateExtkeyByFormatFromSeed(handle, seed, networkType, keyType, formatType, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

// message sign API ------------------------------------------------------------

// CfdGoSignMessage sign messsage.
func CfdGoSignMessage(privkey, message, magic string, isOutputBase64 bool) (signature string, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return signature, err
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdSignMessage(handle, privkey, message, magic, isOutputBase64, &signature)
	err = convertCfdError(ret, handle)
	return signature, err
}

// CfdGoVerifyMessage verify message.
func CfdGoVerifyMessage(signature, pubkey, message, magic string) (recoveredPubkey string, isVerify bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return recoveredPubkey, false, err
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifyMessage(handle, signature, pubkey, message, magic, &recoveredPubkey)
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		isVerify = false
		err = convertCfdError(ret, handle)
	}
	return recoveredPubkey, isVerify, err
}

// CfdGoSetGenesisBlockHashGlobal ...
func CfdGoSetGenesisBlockHashGlobal(genesisBlockHash string) error {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdSetGenesisBlockHashGlobal(handle, genesisBlockHash)
	err = convertCfdError(ret, handle)
	return err
}

// refine API ------------------------------------------------------------------

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

// IssuanceData : confidential transaction issuance input.
type IssuanceData struct {
	Entropy     string
	Nonce       string
	AssetAmount int64
	AssetValue  string
	TokenAmount int64
	TokenValue  string
}

// ConfidentialTxIn : confidential transaction input.
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

// ConfidentialTxOut : confidential transaction output.
type ConfidentialTxOut struct {
	// satoshi amount (unblind value)
	Amount int64
	// asset (or commitment asset)
	Asset string
	// locking script
	LockingScript string
	// address or confidential address. (if locking script is usual hashtype.)
	Address string
	// commitment value
	CommitmentValue string
	// commitment nonce
	CommitmentNonce string
	// surjectionprooof of asset
	Surjectionproof string
	// rangeproof of value
	Rangeproof string
}

// CreateConfidentialTx : create confidential transaction.
// param: version       transaction version.
// param: locktime      transaction locking time.
// param: txinList      transaction input list.
// param: txoutList     transaction output list.
// return: outputTxHex  transaction hex.
// return: err          error
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
			wList := make([]string, wCount)
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
			for j := uint32(0); j < pCount; j++ {
				stackData, err := CfdGoGetTxInWitnessByHandle(handle, 1, i, j)
				if err != nil {
					return data, txinList, txoutList, err
				}
				pList[j] = stackData
			}
			tempTxins[i].PeginWitness.Stack = pList
		}
	}

	tempTxouts := make([]ConfidentialTxOut, txoutCount)
	for i := uint32(0); i < txoutCount; i++ {
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
		if hasAddress && len(tempTxouts[i].LockingScript) > 0 {
			addr, tmpErr := CfdGoGetAddressFromLockingScript(tempTxouts[i].LockingScript, networkType)
			if tmpErr != nil {
				// do nothing
			} else {
				tempTxouts[i].Address = addr
			}
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
