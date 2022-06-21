package tests

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"testing"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestElementsTx(t *testing.T) {
	jsonData := readFile(path.Join(".", "data", "elements_transaction_test.json"))

	testDataArr := []JsonTestData{}
	if err := json.Unmarshal(jsonData, &testDataArr); err != nil {
		panic(err)
	}
	for _, testData := range testDataArr {
		switch testData.Name {
		case "ConfidentialTransaction.SignWithPrivkey":
			testElementsTxSignWithPrivkey(t, &testData)
		case "ConfidentialTransaction.VerifySign":
			testElementsTxVerifySign(t, &testData)
		case "ConfidentialTransaction.VerifySignature":
			testElementsTxVerifySignature(t, &testData)
		case "ConfidentialTransaction.GetSighash":
			testElementsTxGetSighash(t, &testData)
		default:
			// FIXME: not implements
		}
	}
	fmt.Printf("%s test done.\n", GetFuncName())
}

func testElementsTxSignWithPrivkey(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		txHex := testCase.Request["tx"].(string)
		txin := testCase.Request["txin"].(map[string]interface{})
		txid := txin["txid"].(string)
		vout := uint32(txin["vout"].(float64))
		privkey := txin["privkey"].(string)
		hashType := txin["hashType"].(string)
		sighashTypeStr := txin["sighashType"].(string)
		if val, ok := txin["sighashAnyoneCanPay"]; ok && val.(bool) {
			sighashTypeStr += "+anyonecanpay"
		}
		cfdHashType := types.NewHashTypeByString(hashType)
		sighashType := types.NewSigHashTypeFromString(sighashTypeStr)
		var utxos []cfdgo.CfdUtxo
		var amount int64
		var valueCommitment, pubkey string
		if _, ok := testCase.Request["utxos"]; ok {
			// taproot or after
			var genesisBlockHash string
			if _, ok := testCase.Request["genesisBlockHash"]; ok {
				genesisBlockHash = testCase.Request["genesisBlockHash"].(string)
			}
			utxosIF := testCase.Request["utxos"].([]interface{})
			utxos = make([]cfdgo.CfdUtxo, 0, len(utxosIF))
			for _, utxoData := range utxosIF {
				utxo := utxoData.(map[string]interface{})
				var descriptor, asset, valueCommitment string
				var amount int64

				if _, ok := utxo["descriptor"]; ok {
					descriptor = utxo["descriptor"].(string)
				} else if _, ok := utxo["address"]; ok {
					descriptor = fmt.Sprintf("addr(%s)", utxo["address"].(string))
				} else if _, ok := utxo["lockingScript"]; ok {
					descriptor = fmt.Sprintf("raw(%s)", utxo["lockingScript"].(string))
				}
				if _, ok := utxo["asset"]; ok {
					asset = utxo["asset"].(string)
				}
				if _, ok := utxo["amount"]; ok {
					amount = int64(utxo["amount"].(float64))
				}
				if _, ok := utxo["confidentialValueCommitment"]; ok {
					valueCommitment = utxo["confidentialValueCommitment"].(string)
				}
				utxos = append(utxos, cfdgo.CfdUtxo{
					Txid:             utxo["txid"].(string),
					Vout:             uint32(utxo["vout"].(float64)),
					Amount:           amount,
					Asset:            asset,
					Descriptor:       descriptor,
					AmountCommitment: valueCommitment,
					GenesisBlockHash: genesisBlockHash,
				})
			}
		} else {
			// before taproot
			if _, ok := txin["amount"]; ok {
				amount = int64(txin["amount"].(float64))
			}
			if _, ok := txin["confidentialValueCommitment"]; ok {
				valueCommitment = txin["confidentialValueCommitment"].(string)
			}
		}

		var outputTx string
		var err error
		if len(utxos) > 0 {
			outputTx, err = cfdgo.CfdGoAddTxSignWithPrivkeyByUtxoList(
				types.LiquidV1.ToCfdValue(), txHex, utxos, txid, vout, privkey, sighashType.ToCfdValue(), true, nil, nil)
		} else {
			pubkey, err = cfdgo.CfdGoGetPubkeyFromPrivkey("", privkey, true)
			if err == nil {
				outputTx, err = cfdgo.CfdGoAddConfidentialTxSignWithPrivkey(txHex, txid, vout, cfdHashType.ToCfdValue(), pubkey, privkey, amount, valueCommitment, sighashType.GetValue(), sighashType.AnyoneCanPay, true)
			}
		}

		if _, ok := testCase.Expect["hex"]; ok {
			expTxHex := testCase.Expect["hex"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expTxHex, outputTx, testCase.CaseName)
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testElementsTxVerifySign(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		txHex := testCase.Request["tx"].(string)
		txinsIF := testCase.Request["txins"].([]interface{})
		txins := make([]map[string]interface{}, len(txinsIF))
		for i, txinData := range txinsIF {
			txins[i] = txinData.(map[string]interface{})
		}
		txin := txins[0]
		txid := txin["txid"].(string)
		vout := uint32(txin["vout"].(float64))
		var utxos []cfdgo.CfdUtxo
		var amount int64
		var addressType types.AddressType
		var valueCommitment, address, directLockingScript string
		if _, ok := testCase.Request["utxos"]; ok {
			// taproot or after
			var genesisBlockHash string
			if _, ok := testCase.Request["genesisBlockHash"]; ok {
				genesisBlockHash = testCase.Request["genesisBlockHash"].(string)
			}
			utxosIF := testCase.Request["utxos"].([]interface{})
			utxos = make([]cfdgo.CfdUtxo, 0, len(utxosIF))
			for _, utxoData := range utxosIF {
				utxo := utxoData.(map[string]interface{})
				var descriptor, asset, valueCommitment string
				var amount int64

				if _, ok := utxo["descriptor"]; ok {
					descriptor = utxo["descriptor"].(string)
				} else if _, ok := utxo["address"]; ok {
					descriptor = fmt.Sprintf("addr(%s)", utxo["address"].(string))
				} else if _, ok := utxo["lockingScript"]; ok {
					descriptor = fmt.Sprintf("raw(%s)", utxo["lockingScript"].(string))
				}
				if _, ok := utxo["asset"]; ok {
					asset = utxo["asset"].(string)
				}
				if _, ok := utxo["amount"]; ok {
					amount = int64(utxo["amount"].(float64))
				}
				if _, ok := utxo["confidentialValueCommitment"]; ok {
					valueCommitment = utxo["confidentialValueCommitment"].(string)
				}
				utxos = append(utxos, cfdgo.CfdUtxo{
					Txid:             utxo["txid"].(string),
					Vout:             uint32(utxo["vout"].(float64)),
					Amount:           amount,
					Asset:            asset,
					Descriptor:       descriptor,
					AmountCommitment: valueCommitment,
					GenesisBlockHash: genesisBlockHash,
				})
			}
		} else {
			// before taproot
			if _, ok := txin["amount"]; ok {
				amount = int64(txin["amount"].(float64))
			}
			if _, ok := txin["confidentialValueCommitment"]; ok {
				valueCommitment = txin["confidentialValueCommitment"].(string)
			}
			if addr, ok := txin["address"]; ok && addr.(string) != "" {
				address = txin["address"].(string)
			} else if desc, ok := txin["descriptor"]; ok && desc.(string) != "" {
				descriptor := txin["descriptor"].(string)
				data, _, _, err := cfdgo.CfdGoParseDescriptorData(descriptor, types.ElementsRegtest.ToCfdValue(), "")
				assert.NoError(t, err, testCase.CaseName)
				if err == nil {
					address = data.Address
				}
			} else if _, ok := txin["lockingScript"]; ok {
				directLockingScript = txin["lockingScript"].(string)
			}

			if address != "" {
				addrInfo, err := cfdgo.CfdGoGetAddressInfo(address)
				assert.NoError(t, err)
				if err == nil {
					addressType = types.NewAddressTypeByHashType(addrInfo.HashType)
				}
			}
		}

		var isVerify bool
		var reason string
		var err error
		if len(utxos) > 0 {
			isVerify, reason, err = cfdgo.CfdGoVerifySign(types.ElementsRegtest.ToCfdValue(), txHex, utxos, txid, vout)
		} else {
			isVerify, reason, err = cfdgo.CfdGoVerifyConfidentialTxSignReason(txHex, txid, vout, address, addressType.ToCfdValue(), directLockingScript, amount, valueCommitment)
		}

		if _, ok := testCase.Expect["success"]; ok {
			expSuccess := testCase.Expect["success"].(bool)
			expFailTxinsIF := testCase.Expect["failTxins"].([]interface{})
			type FailTxIns struct {
				TxID   string
				Vout   uint32
				Reason string
			}
			expFailTxins := make([]FailTxIns, 0, len(expFailTxinsIF))
			for _, failTxInData := range expFailTxinsIF {
				failTxIn := failTxInData.(map[string]interface{})
				expFailTxins = append(expFailTxins, FailTxIns{
					TxID:   failTxIn["txid"].(string),
					Vout:   uint32(failTxIn["vout"].(float64)),
					Reason: failTxIn["reason"].(string),
				})
			}

			assert.NoError(t, err)
			assert.Equal(t, expSuccess, isVerify, testCase.CaseName, txins)
			if !isVerify {
				assert.Equal(t, 1, len(expFailTxins), testCase.CaseName)
				assert.Equal(t, expFailTxins[0].TxID, txid, testCase.CaseName)
				assert.Equal(t, expFailTxins[0].Vout, vout, testCase.CaseName)
				assert.Equal(t, expFailTxins[0].Reason, reason, testCase.CaseName)
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testElementsTxVerifySignature(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		txHex := testCase.Request["tx"].(string)
		txin := testCase.Request["txin"].(map[string]interface{})
		txid := txin["txid"].(string)
		vout := uint32(txin["vout"].(float64))
		signature := txin["signature"].(string)
		pubkey := txin["pubkey"].(string)
		hashType := txin["hashType"].(string)
		sighashTypeStr := txin["sighashType"].(string)
		if val, ok := txin["sighashAnyoneCanPay"]; ok && val.(bool) {
			sighashTypeStr += "+anyonecanpay"
		}
		cfdHashType := types.NewHashTypeByString(hashType)
		sighashType := types.NewSigHashTypeFromString(sighashTypeStr)
		var utxos []cfdgo.CfdUtxo
		var amount int64
		var valueCommitment string
		if _, ok := testCase.Request["utxos"]; ok {
			// taproot or after
			var genesisBlockHash string
			if _, ok := testCase.Request["genesisBlockHash"]; ok {
				genesisBlockHash = testCase.Request["genesisBlockHash"].(string)
			}
			utxosIF := testCase.Request["utxos"].([]interface{})
			utxos = make([]cfdgo.CfdUtxo, 0, len(utxosIF))
			for _, utxoData := range utxosIF {
				utxo := utxoData.(map[string]interface{})
				var descriptor, asset, valueCommitment string
				var amount int64

				if _, ok := utxo["descriptor"]; ok {
					descriptor = utxo["descriptor"].(string)
				} else if _, ok := utxo["address"]; ok {
					descriptor = fmt.Sprintf("addr(%s)", utxo["address"].(string))
				} else if _, ok := utxo["lockingScript"]; ok {
					descriptor = fmt.Sprintf("raw(%s)", utxo["lockingScript"].(string))
				}
				if _, ok := utxo["asset"]; ok {
					asset = utxo["asset"].(string)
				}
				if _, ok := utxo["amount"]; ok {
					amount = int64(utxo["amount"].(float64))
				}
				if _, ok := utxo["confidentialValueCommitment"]; ok {
					valueCommitment = utxo["confidentialValueCommitment"].(string)
				}
				utxos = append(utxos, cfdgo.CfdUtxo{
					Txid:             utxo["txid"].(string),
					Vout:             uint32(utxo["vout"].(float64)),
					Amount:           amount,
					Asset:            asset,
					Descriptor:       descriptor,
					AmountCommitment: valueCommitment,
					GenesisBlockHash: genesisBlockHash,
				})
			}
		} else {
			// before taproot
			if _, ok := txin["amount"]; ok {
				amount = int64(txin["amount"].(float64))
			}
			if _, ok := txin["confidentialValueCommitment"]; ok {
				valueCommitment = txin["confidentialValueCommitment"].(string)
			}
		}

		var isVerify bool
		var sighash string
		var err error
		if len(utxos) > 0 {
			sighash, err = cfdgo.CfdGoGetSighash(types.ElementsRegtest.ToCfdValue(), txHex, utxos, txid, vout, sighashType.ToCfdValue(), cfdgo.NewByteDataFromHexIgnoreError(pubkey), nil, nil, nil, nil)
			switch {
			case err != nil: // do nothing
			case len(pubkey) == 64:
				// taproot
				util := cfdgo.NewSchnorrUtil()
				isVerify, err = util.Verify(*cfdgo.NewByteDataFromHexIgnoreError(signature),
					*cfdgo.NewByteDataFromHexIgnoreError(sighash),
					*cfdgo.NewByteDataFromHexIgnoreError(pubkey))
			case len(pubkey) == 66:
				// not taproot
				isVerify, err = cfdgo.CfdGoVerifyEcSignature(sighash, pubkey, signature)
			}
		} else {
			isVerify, err = cfdgo.CfdGoVerifyConfidentialTxSignature(txHex, signature, pubkey, "", txid, vout, sighashType.GetValue(), sighashType.AnyoneCanPay, amount, valueCommitment, cfdHashType.GetWitnessVersion())
		}

		if _, ok := testCase.Expect["success"]; ok {
			expSuccess := testCase.Expect["success"].(bool)

			assert.NoError(t, err)
			assert.Equal(t, expSuccess, isVerify, testCase.CaseName)
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if expErr == "" || err == nil {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testElementsTxGetSighash(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		txHex := testCase.Request["tx"].(string)
		txin := testCase.Request["txin"].(map[string]interface{})
		txid := txin["txid"].(string)
		vout := uint32(txin["vout"].(float64))
		hashType := txin["hashType"].(string)
		sighashTypeStr := txin["sighashType"].(string)
		if val, ok := txin["sighashAnyoneCanPay"]; ok && val.(bool) {
			sighashTypeStr += "+anyonecanpay"
		}
		cfdHashType := types.NewHashTypeByString(hashType)
		sighashType := types.NewSigHashTypeFromString(sighashTypeStr)

		var utxos []cfdgo.CfdUtxo
		var amount int64
		var valueCommitment, pubkey, redeemScript string
		keyData := txin["keyData"].(map[string]interface{})
		keyHex := keyData["hex"].(string)
		keyType := keyData["type"].(string)
		switch keyType {
		case "pubkey":
			pubkey = keyHex
		case "redeem_script":
			redeemScript = keyHex
		default:
			assert.Fail(t, "invalid keytype.", keyType)
		}

		if _, ok := testCase.Request["utxos"]; ok {
			// taproot or after
			var genesisBlockHash string
			if _, ok := testCase.Request["genesisBlockHash"]; ok {
				genesisBlockHash = testCase.Request["genesisBlockHash"].(string)
			}
			utxosIF := testCase.Request["utxos"].([]interface{})
			utxos = make([]cfdgo.CfdUtxo, 0, len(utxosIF))
			for _, utxoData := range utxosIF {
				utxo := utxoData.(map[string]interface{})
				var descriptor, asset, valueCommitment string
				var amount int64

				if _, ok := utxo["descriptor"]; ok {
					descriptor = utxo["descriptor"].(string)
				} else if _, ok := utxo["address"]; ok {
					descriptor = fmt.Sprintf("addr(%s)", utxo["address"].(string))
				} else if _, ok := utxo["lockingScript"]; ok {
					descriptor = fmt.Sprintf("raw(%s)", utxo["lockingScript"].(string))
				}
				if _, ok := utxo["asset"]; ok {
					asset = utxo["asset"].(string)
				}
				if _, ok := utxo["amount"]; ok {
					amount = int64(utxo["amount"].(float64))
				}
				if _, ok := utxo["confidentialValueCommitment"]; ok {
					valueCommitment = utxo["confidentialValueCommitment"].(string)
				}
				utxos = append(utxos, cfdgo.CfdUtxo{
					Txid:             utxo["txid"].(string),
					Vout:             uint32(utxo["vout"].(float64)),
					Amount:           amount,
					Asset:            asset,
					Descriptor:       descriptor,
					AmountCommitment: valueCommitment,
					GenesisBlockHash: genesisBlockHash,
				})
			}
		} else {
			// before taproot
			if _, ok := txin["amount"]; ok {
				amount = int64(txin["amount"].(float64))
			}
			if _, ok := txin["confidentialValueCommitment"]; ok {
				valueCommitment = txin["confidentialValueCommitment"].(string)
			}
		}

		var sighash string
		var err error
		if len(utxos) > 0 {
			sighash, err = cfdgo.CfdGoGetSighash(types.ElementsRegtest.ToCfdValue(), txHex, utxos, txid, vout, sighashType.ToCfdValue(), cfdgo.NewByteDataFromHexIgnoreError(pubkey),
				cfdgo.NewScriptFromHexIgnoreError(redeemScript), nil, nil, nil)
		} else {
			sighash, err = cfdgo.CfdGoCreateConfidentialSighash(txHex, txid, vout, cfdHashType.ToCfdValue(), pubkey, redeemScript, amount, valueCommitment, sighashType.GetValue(), sighashType.AnyoneCanPay)
		}

		if _, ok := testCase.Expect["sighash"]; ok {
			expSighash := testCase.Expect["sighash"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expSighash, sighash, testCase.CaseName, utxos, pubkey, redeemScript)
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}
