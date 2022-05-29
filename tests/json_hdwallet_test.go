package tests

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"testing"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestHDWallet(t *testing.T) {
	jsonData := readFile(path.Join(".", "data", "hdwallet_test.json"))

	testDataArr := []JsonTestData{}
	if err := json.Unmarshal(jsonData, &testDataArr); err != nil {
		panic(err)
	}
	for _, testData := range testDataArr {
		switch testData.Name {
		case "HDWallet.GetExtPrivkeyFromSeed":
			testGetExtPrivkeyFromSeed(t, &testData)
		case "Extkey.GetExtPubkey":
			testGetExtPubkey(t, &testData)
		case "Extkey.CreateExtkeyFromParent":
			testCreateExtkeyFromParent(t, &testData)
		case "Extkey.CreateExtkeyFromParentPath":
			testCreateExtkeyFromParentPath(t, &testData)
		case "Extkey.GetExtkeyInfo":
			testGetExtkeyInfo(t, &testData)
		case "Extkey.CreateExtkey":
			testCreateExtkey(t, &testData)
		case "Extkey.CreateExtkeyFromParentKey":
			testCreateExtkeyFromParentKey(t, &testData)
		case "Extkey.GetPrivkeyFromExtkey":
			testGetPrivkeyFromExtkey(t, &testData)
		case "Extkey.GetPubkeyFromExtkey":
			testGetPubkeyFromExtkey(t, &testData)
		default:
			// FIXME: not implements
		}
	}
	fmt.Printf("%s test done.\n", GetFuncName())
}

func testGetExtPrivkeyFromSeed(t *testing.T, testData *JsonTestData) {
	var err error
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		switch testCase.CaseName {
		case "privkey", "pubkey":
			// FIXME: need implements
		default:
			seed := testCase.Request["seed"].(string)
			network := testCase.Request["network"].(string)
			extkeyType := testCase.Request["extkeyType"].(string)
			var bip32FormatType string
			if _, ok := testCase.Request["bip32FormatType"]; ok {
				bip32FormatType = testCase.Request["bip32FormatType"].(string)
			}
			networkType := types.NewNetworkTypeByString(network)
			keyType := types.NewExtkeyTypeByString(extkeyType)
			var extkey string
			if bip32FormatType == "" {
				extkey, err = cfdgo.CfdGoCreateExtkeyFromSeed(seed, networkType.ToCfdValue(), keyType.ToCfdValue())
			} else {
				formatType := types.NewExtkeyFormatTypeByString(bip32FormatType)
				extkey, err = cfdgo.CfdGoCreateExtkeyByFormatFromSeed(seed, networkType.ToCfdValue(), keyType.ToCfdValue(), formatType.ToCfdValue())
			}
			if _, ok := testCase.Expect["extkey"]; ok {
				expExtkey := testCase.Expect["extkey"].(string)
				assert.NoError(t, err)
				assert.Equal(t, expExtkey, extkey)
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
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testGetExtPubkey(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		if testCase.CaseName == "normal" {
			// FIXME: need implements
		} else {
			extkey := testCase.Request["extkey"].(string)
			network := testCase.Request["network"].(string)
			networkType := types.NewNetworkTypeByString(network)
			extPubkey, err := cfdgo.CfdGoCreateExtPubkey(extkey, networkType.ToCfdValue())
			if _, ok := testCase.Expect["extkey"]; ok {
				expExtkey := testCase.Expect["extkey"].(string)
				assert.NoError(t, err)
				assert.Equal(t, expExtkey, extPubkey)
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
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testCreateExtkeyFromParent(t *testing.T, testData *JsonTestData) {
	// var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		// TODO: Not implemented now because the test data does not match the golang interface. Will implement after reconfirming the cfd-go interface.
	}

	// fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testCreateExtkeyFromParentPath(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		extkey := testCase.Request["extkey"].(string)
		network := testCase.Request["network"].(string)
		extkeyType := testCase.Request["extkeyType"].(string)
		var path string
		if _, ok := testCase.Request["path"]; ok {
			path = testCase.Request["path"].(string)
		} else if _, ok := testCase.Request["childNumberArray"]; ok {
			childNumberArrayIF := testCase.Request["childNumberArray"].([]interface{})
			for i, childNumberIF := range childNumberArrayIF {
				if i > 0 {
					path += "/"
				}
				path += strconv.FormatInt(int64(childNumberIF.(float64)), 10)
			}
		}
		networkType := types.NewNetworkTypeByString(network)
		keyType := types.NewExtkeyTypeByString(extkeyType)
		childKey, err := cfdgo.CfdGoCreateExtkeyFromParentPath(extkey, path, networkType.ToCfdValue(), keyType.ToCfdValue())
		if _, ok := testCase.Expect["extkey"]; ok {
			expExtkey := testCase.Expect["extkey"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expExtkey, childKey)
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

func testGetExtkeyInfo(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		extkey := testCase.Request["extkey"].(string)
		extkeyData, keyType, networkType, err := cfdgo.CfdGoGetExtkeyInfo(extkey)
		if _, ok := testCase.Expect["version"]; ok {
			network := testCase.Expect["network"].(string)
			version := testCase.Expect["version"].(string)
			depth := int64(testCase.Expect["depth"].(float64))
			fingerprint := testCase.Expect["fingerprint"].(string)
			childNumber := int64(testCase.Expect["childNumber"].(float64))
			chainCode := testCase.Expect["chainCode"].(string)
			extkeyType := testCase.Expect["keyType"].(string)

			expNetworkType := types.NewNetworkTypeByString(network)
			expKeyType := types.NewExtkeyTypeByString(extkeyType)
			assert.NoError(t, err)
			assert.Equal(t, expNetworkType.ToCfdValue(), networkType)
			assert.Equal(t, expKeyType.ToCfdValue(), keyType)
			assert.Equal(t, version, extkeyData.Version)
			assert.Equal(t, uint32(depth), extkeyData.Depth)
			assert.Equal(t, uint32(childNumber), extkeyData.ChildNumber)
			assert.Equal(t, fingerprint, extkeyData.Fingerprint)
			assert.Equal(t, chainCode, extkeyData.ChainCode)
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

func testCreateExtkey(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		network := testCase.Request["network"].(string)
		extkeyType := testCase.Request["extkeyType"].(string)
		parentFingerprint := testCase.Request["parentFingerprint"].(string)
		key := testCase.Request["key"].(string)
		depth := int64(testCase.Request["depth"].(float64))
		chainCode := testCase.Request["chainCode"].(string)
		childNumberInt64 := int64(testCase.Request["childNumber"].(float64))
		hardened := testCase.Request["hardened"].(bool)
		childNumber := uint32(childNumberInt64)
		if hardened {
			childNumber |= uint32(0x80000000)
		}
		var bip32FormatType string
		if _, ok := testCase.Request["bip32FormatType"]; ok {
			bip32FormatType = testCase.Request["bip32FormatType"].(string)
		}
		networkType := types.NewNetworkTypeByString(network)
		keyType := types.NewExtkeyTypeByString(extkeyType)
		var extkey string
		var err error
		if bip32FormatType == "" {
			extkey, err = cfdgo.CfdGoCreateExtkey(networkType.ToCfdValue(), keyType.ToCfdValue(), parentFingerprint, key, chainCode, byte(depth), childNumber)
		} else {
			formatType := types.NewExtkeyFormatTypeByString(bip32FormatType)
			extkey, err = cfdgo.CfdGoCreateExtkeyByFormat(networkType.ToCfdValue(), keyType.ToCfdValue(), parentFingerprint, key, chainCode, byte(depth), childNumber, formatType.ToCfdValue())
		}
		if _, ok := testCase.Expect["extkey"]; ok {
			expExtkey := testCase.Expect["extkey"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expExtkey, extkey)
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

func testCreateExtkeyFromParentKey(t *testing.T, testData *JsonTestData) {
	//var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		// TODO: Not implemented now because the test data does not match the golang interface. Will implement after reconfirming the cfd-go interface.
		/*
			network := testCase.Request["network"].(string)
			extkeyType := testCase.Request["extkeyType"].(string)
			parentKey := testCase.Request["parentKey"].(string)
			parentDepth := int64(testCase.Request["parentDepth"].(float64))
			parentChainCode := testCase.Request["parentChainCode"].(string)
			childNumberInt64 := int64(testCase.Request["childNumber"].(float64))
			hardened := testCase.Request["hardened"].(bool)
			childNumber := uint32(childNumberInt64)
			if hardened {
				childNumber |= uint32(0x80000000)
			}
			var bip32FormatType string
			if _, ok := testCase.Request["bip32FormatType"]; ok {
				bip32FormatType = testCase.Request["bip32FormatType"].(string)
			}
			networkType := types.NewNetworkTypeByString(network)
			keyType := types.NewExtkeyTypeByString(extkeyType)
			var extkey string
			var err error
			if bip32FormatType == "" {
				extkey, err = cfdgo.CfdGoCreateExtkeyFromParent(networkType.ToCfdValue(), keyType.ToCfdValue(), parentKey, "", parentChainCode, byte(parentDepth), childNumber)
			} else {
				formatType := types.NewExtkeyFormatTypeByString(bip32FormatType)
				extkey, err = cfdgo.CfdGoCreateExtkeyByFormatFromParent(networkType.ToCfdValue(), keyType.ToCfdValue(), parentKey, "", parentChainCode, byte(parentDepth), childNumber, formatType.ToCfdValue())
			}
			if _, ok := testCase.Expect["extkey"]; ok {
				expExtkey := testCase.Expect["extkey"].(string)
				assert.NoErrorf(t, err, testCase.CaseName)
				assert.Equal(t, expExtkey, extkey)
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
		*/
	}

	//fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testGetPrivkeyFromExtkey(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		extkey := testCase.Request["extkey"].(string)
		network := testCase.Request["network"].(string)
		isWif := testCase.Request["wif"].(bool)
		isCompressed := testCase.Request["isCompressed"].(bool)

		networkType := types.NewNetworkTypeByString(network)
		privkeyHex, wif, err := cfdgo.CfdGoGetPrivkeyFromExtkey(extkey, networkType.ToCfdValue())
		if _, ok := testCase.Expect["privkey"]; ok {
			expPrivkey := testCase.Expect["privkey"].(string)
			assert.NoError(t, err)
			if isCompressed {
				if isWif {
					assert.Equal(t, expPrivkey, wif)
				} else {
					assert.Equal(t, expPrivkey, privkeyHex)
				}
			} // `isCompressed=false` is unsupported.

			hexStr, nw, isComp, err := cfdgo.CfdGoParsePrivkeyWif(wif)
			assert.NoError(t, err)
			assert.Equal(t, hexStr, privkeyHex)
			assert.Equal(t, networkType.ToCfdValue(), nw)
			if isCompressed {
				assert.Equal(t, isCompressed, isComp)
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

func testGetPubkeyFromExtkey(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		extkey := testCase.Request["extkey"].(string)
		network := testCase.Request["network"].(string)

		networkType := types.NewNetworkTypeByString(network)
		pk, err := cfdgo.CfdGoGetPubkeyFromExtkey(extkey, networkType.ToCfdValue())
		if _, ok := testCase.Expect["pubkey"]; ok {
			expPubkey := testCase.Expect["pubkey"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expPubkey, pk)
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
