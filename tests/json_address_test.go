package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestAddress(t *testing.T) {
	jsonData := readFile(path.Join(".", "data", "address_test.json"))

	testDataArr := []JsonTestData{}
	if err := json.Unmarshal(jsonData, &testDataArr); err != nil {
		panic(err)
	}
	for _, testData := range testDataArr {
		switch testData.Name {
		case "Address.Create":
			testAddressCreate(t, &testData)
		case "Address.GetInfo":
			testAddressGetInfo(t, &testData)
		case "Address.MultisigAddresses":
			testAddressMultisigAddresses(t, &testData)
		case "Address.CreateMultisig":
			testAddressCreateMultisig(t, &testData)
		case "Address.FromLockingScript":
			testAddressFromLockingScript(t, &testData)
		case "Address.GetTapScriptTreeInfo":
			testAddressGetTapScriptTreeInfo(t, &testData)
		case "Address.GetTapScriptTreeInfoByControlBlock":
			testAddressGetTapScriptTreeInfoByControlBlock(t, &testData)
		case "Address.GetTapScriptTreeFromString":
			testAddressGetTapScriptTreeFromString(t, &testData)
		case "Address.GetTapBranchInfo":
			testAddressGetTapBranchInfo(t, &testData)
		case "Address.AnalyzeTapScriptTree":
			//testAddressAnalyzeTapScriptTree(t, &testData)
		default:
			assert.Fail(t, "test not implements, ", testData.Name)
		}
		//time.Sleep(1000 * time.Millisecond)
	}
	assert.True(t, true)
	fmt.Printf("%s test done.\n", GetFuncName())
	_ = os.Stdout.Sync()
	time.Sleep(time.Second)
}

func testAddressCreate(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		keyData := testCase.Request["keyData"].(map[string]interface{})
		typeStr := keyData["type"].(string)
		network := testCase.Request["network"].(string)
		hashType := testCase.Request["hashType"].(string)
		cfdHashType := types.NewHashTypeByString(hashType)
		networkType := types.NewNetworkTypeByString(network)
		var pubkey, redeemScript string
		switch typeStr {
		case "pubkey":
			pubkey = keyData["hex"].(string)
		case "redeem_script":
			redeemScript = keyData["hex"].(string)
		default:
			assert.Fail(t, "invalid types,", typeStr, testCase.CaseName)
		}

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		address, lockingScript, p2shScript, err := cfdgo.CfdGoCreateAddress(cfdHashType.ToCfdValue(), pubkey, redeemScript, networkType.ToCfdValue())
		if _, ok := testCase.Expect["address"]; ok {
			expAddress := testCase.Expect["address"].(string)
			expLockingScript := testCase.Expect["lockingScript"].(string)

			assert.NoError(t, err)
			assert.Equal(t, expAddress, address)
			assert.Equal(t, expLockingScript, lockingScript)

			if hashType == "p2sh-p2wsh" || hashType == "p2sh-p2wpkh" {
				expRedeemScript := testCase.Expect["redeemScript"].(string)
				assert.Equal(t, expRedeemScript, p2shScript)
			} else {
				assert.Empty(t, p2shScript)
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressGetInfo(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
		   "request": {
		       "isElements": false,
		       "address": "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
		   },
		   "expect": {
		       "lockingScript": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
		       "network": "mainnet",
		       "hashType": "p2wsh",
		       "witnessVersion": 0,
		       "hash": "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
		   }
		*/

		address := testCase.Request["address"].(string)
		isElements := testCase.Request["isElements"].(bool)
		data, err := cfdgo.CfdGoGetAddressInfo(address)
		if _, ok := testCase.Expect["network"]; ok {
			// network := testCase.Expect["network"].(string)
			networkType := types.NewNetworkType(data.NetworkType)
			hashType := types.NewHashType(data.HashType)
			expNetwork := testCase.Expect["network"].(string)
			expHashType := testCase.Expect["hashType"].(string)
			expLockingScript := testCase.Expect["lockingScript"].(string)
			expHash := testCase.Expect["hash"].(string)
			var expWitnessVer int = -1
			if _, ok := testCase.Expect["witnessVersion"]; ok {
				expWitnessVer = int(testCase.Expect["witnessVersion"].(float64))
			}

			assert.NoError(t, err)
			assert.Equal(t, expLockingScript, data.LockingScript)
			if isElements && expNetwork == "regtest" {
				assert.Equal(t, types.ElementsRegtest.String(), networkType.String())
			} else {
				assert.Equal(t, expNetwork, strings.ToLower(networkType.String()), testCase.CaseName)
			}
			assert.Equal(t, expHashType, hashType.String())
			assert.Equal(t, expHash, data.Hash)
			assert.Equal(t, expWitnessVer, data.WitnessVersion)
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressMultisigAddresses(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
				"request": {
					"isElements": false,
					"redeemScript": "522103789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd2103dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a6162652ae",
					"network": "testnet",
					"hashType": "p2sh-p2wpkh"
			},
			"expect": {
					"addresses": [
							"2N84C9EbDYXY6GgzwV5KpRZhS3FxF5jrHx6",
							"2N4pHB8qf9rwUsSu1i79vAYoyyGTYgeFvX9"
					],
					"pubkeys": [
							"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
							"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
					],
					"requireNum": 2
			}
		*/

		redeemScript := testCase.Request["redeemScript"].(string)
		network := testCase.Request["network"].(string)
		hashType := testCase.Request["hashType"].(string)
		cfdHashType := types.NewHashTypeByString(hashType)
		networkType := types.NewNetworkTypeByString(network)

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		addrs, pubkeys, err := cfdgo.CfdGoGetAddressesFromMultisig(
			redeemScript, networkType.ToCfdValue(), cfdHashType.ToCfdValue())
		if _, ok := testCase.Expect["addresses"]; ok {
			expAddressesIF := testCase.Expect["addresses"].([]interface{})
			expPubkeysIF := testCase.Expect["pubkeys"].([]interface{})
			//expReqNum := int(testCase.Expect["requireNum"].(float64))
			expAddrs := make(map[string]bool, len(expAddressesIF))
			expPubkeys := make(map[string]bool, len(expPubkeysIF))
			for i := range expAddressesIF {
				addr := expAddressesIF[i].(string)
				expAddrs[addr] = true
			}
			for i := range expPubkeysIF {
				pk := expPubkeysIF[i].(string)
				expPubkeys[pk] = true
			}

			assert.NoError(t, err)
			assert.Equal(t, len(expAddrs), len(addrs))
			assert.Equal(t, len(expPubkeys), len(pubkeys))
			for _, addr := range addrs {
				assert.True(t, expAddrs[addr], "address not found,", addr, testCase.CaseName)
				delete(expAddrs, addr)
			}
			for _, pk := range pubkeys {
				assert.True(t, expPubkeys[pk], "pubkey not found,", pk, testCase.CaseName)
				delete(expPubkeys, pk)
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressCreateMultisig(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
		   "request": {
		       "nrequired": 2,
		       "keys": [
		           "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
		           "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
		       ],
		       "network": "regtest",
		       "hashType": "p2sh-p2wsh"
		   },
		   "expect": {
		       "address": "2MtrgHUaouokgnbFVdrbJCwtrcTnyKUWi3o",
		       "redeemScript": "00207ca68449d39a95da91c6c283871f587b74b45c1645a37f8c8337fd3d9ac4fee6",
		       "witnessScript": "522103789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd2103dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a6162652ae"
		   }
		*/

		reqNum := uint32(testCase.Request["nrequired"].(float64))
		keysIF := testCase.Request["keys"].([]interface{})
		keys := make([]string, len(keysIF))
		for i := range keysIF {
			keys[i] = keysIF[i].(string)
		}
		network := testCase.Request["network"].(string)
		hashType := testCase.Request["hashType"].(string)
		cfdHashType := types.NewHashTypeByString(hashType)
		networkType := types.NewNetworkTypeByString(network)

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		address, redeemScript, witnessScript, err := cfdgo.CfdGoCreateMultisigScript(
			networkType.ToCfdValue(), cfdHashType.ToCfdValue(), keys, reqNum)
		if _, ok := testCase.Expect["address"]; ok {
			expAddress := testCase.Expect["address"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expAddress, address)

			switch hashType {
			case "p2sh":
				expRedeemScript := testCase.Expect["redeemScript"].(string)
				assert.Equal(t, expRedeemScript, redeemScript)
			case "p2sh-p2wsh":
				expRedeemScript := testCase.Expect["redeemScript"].(string)
				assert.Equal(t, expRedeemScript, redeemScript)
				expWitnessScript := testCase.Expect["witnessScript"].(string)
				assert.Equal(t, expWitnessScript, witnessScript)
			case "p2wsh":
				expWitnessScript := testCase.Expect["witnessScript"].(string)
				assert.Equal(t, expWitnessScript, witnessScript)
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressFromLockingScript(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
			"request": {
					"lockingScript": "51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
					"network": "regtest"
			},
			"expect": {
					"address": "bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq",
					"hashType": "taproot"
			},
		*/

		network := testCase.Request["network"].(string)
		lockingScript := testCase.Request["lockingScript"].(string)
		networkType := types.NewNetworkTypeByString(network)

		address, err := cfdgo.CfdGoGetAddressFromLockingScript(lockingScript, networkType.ToCfdValue())
		if _, ok := testCase.Expect["address"]; ok {
			expAddress := testCase.Expect["address"].(string)

			assert.NoError(t, err)
			assert.Equal(t, expAddress, address)
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressGetTapScriptTreeInfo(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
			"request": {
					"network": "mainnet",
					"isElements": false,
					"internalPubkey": "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
					"tree": [
							{
									"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac"
							},
							{
									"branchHash": "4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"
							},
							{
									"branchHash": "dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54"
							}
					]
			},
			"expect": {
					"tapLeafHash": "dfc43ba9fc5f8a9e1b6d6a50600c704bb9e41b741d9ed6de6559a53d2f38e513",
					"topBranchHash": "09659d67a7a6fb82c1e382fd8f99f6bb43cbd80883845c6df7029f9589fc7af3",
					"tweakedPubkey": "3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"address": "bc1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fqw77n40",
					"lockingScript": "51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"controlBlock": "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
					"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
					"nodes": [
							"4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
							"dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54"
					],
					"treeString": "{{4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)},dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54}"
			}
		*/

		treeList := testCase.Request["tree"].([]interface{})
		network := "mainnet"
		if _, ok := testCase.Request["network"]; ok {
			network = testCase.Request["network"].(string)
		}
		networkType := types.NewNetworkTypeByString(network)
		assert.NotEqual(t, types.Unknown, networkType)
		var internalPubkey, internalPrivkey string
		if _, ok := testCase.Request["internalPubkey"]; ok {
			internalPubkey = testCase.Request["internalPubkey"].(string)
		}
		if _, ok := testCase.Request["internalPrivkey"]; ok {
			internalPrivkey = testCase.Request["internalPrivkey"].(string)
		}

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		var branch *cfdgo.TapBranch
		var err error
		var tapscript string
		for i := range treeList {
			dataMap := treeList[i].(map[string]interface{})
			if branch == nil {
				if _, ok := dataMap["tapscript"]; ok {
					tapscript = dataMap["tapscript"].(string)
					branch, err = cfdgo.NewTapBranchFromTapScriptWithNetwork(cfdgo.NewScriptFromHexIgnoreError(tapscript), networkType.ToCfdValue())
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else if _, ok := dataMap["treeString"]; ok {
					treeString := dataMap["treeString"].(string)
					branch, err = cfdgo.NewTapBranchFromStringWithNetwork(treeString, nil, networkType.ToCfdValue())
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else if _, ok := dataMap["branchHash"]; ok {
					branchHash := dataMap["branchHash"].(string)
					branch, err = cfdgo.NewTapBranchFromHashWithNetwork(cfdgo.NewByteDataFromHexIgnoreError(branchHash), networkType.ToCfdValue())
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else {
					panic(fmt.Sprintf("invalid script tree data, test:%s, case:%s, dataMap:%v", testData.Name, testCase.CaseName, dataMap))
				}
			} else {
				if _, ok := dataMap["tapscript"]; ok {
					tapscript := dataMap["tapscript"].(string)
					err = branch.AddBranchByTapScript(cfdgo.NewScriptFromHexIgnoreError(tapscript))
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else if _, ok := dataMap["treeString"]; ok {
					treeString := dataMap["treeString"].(string)
					err = branch.AddBranchByString(treeString)
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else if _, ok := dataMap["branchHash"]; ok {
					branchHash := dataMap["branchHash"].(string)
					err = branch.AddBranchByHash(cfdgo.NewByteDataFromHexIgnoreError(branchHash))
					if err != nil {
						assert.NoError(t, err)
						break
					}
				} else {
					panic(fmt.Sprintf("invalid script tree data, test:%s, case:%s, dataMap:%v", testData.Name, testCase.CaseName, dataMap))
				}
			}
		}

		nodes := []string{}
		var treeString, address, lockingScript string
		var tapScript cfdgo.Script
		var topBranchHash, tweakedPubkey, tapLeafHash, controlBlock, tweakedPrivkey *cfdgo.ByteData
		if err == nil && branch != nil {
			nodes, err = branch.GetControlNodeList()
			assert.NoError(t, err)
			treeString = branch.GetTreeString()
			topBranchHash = &branch.Hash
			tapScript = branch.TapScript
			if internalPubkey != "" {
				tweakedPubkey, tapLeafHash, controlBlock, err = branch.GetTweakedPubkey(
					cfdgo.NewByteDataFromHexIgnoreError(internalPubkey))
				assert.NoError(t, err)
				if err == nil {
					address, lockingScript, _, err = cfdgo.CfdGoCreateAddress(types.Taproot.ToCfdValue(), tweakedPubkey.ToHex(), "", networkType.ToCfdValue())
					assert.NoError(t, err)
				}
			}
			if err == nil && internalPrivkey != "" {
				tweakedPrivkey, err = branch.GetTweakedPrivkey(cfdgo.NewByteDataFromHexIgnoreError(internalPrivkey))
				assert.NoError(t, err)
			}
		}

		if _, ok := testCase.Expect["treeString"]; ok {
			expTreeString := testCase.Expect["treeString"].(string)
			expTopBranchHash := testCase.Expect["topBranchHash"].(string)
			expTapScript := ""
			if _, ok := testCase.Expect["tapscript"]; ok {
				expTapScript = testCase.Expect["tapscript"].(string)
			}

			expNodes := make([]string, 0, len(nodes))
			if _, ok := testCase.Expect["nodes"]; ok {
				expNodesIF := testCase.Expect["nodes"].([]interface{})
				for i := range expNodesIF {
					expNodes = append(expNodes, expNodesIF[i].(string))
				}
			}

			assert.NoError(t, err)
			assert.Equal(t, expTreeString, treeString, testCase.CaseName)
			assert.Equal(t, expNodes, nodes)
			assert.Equal(t, expTapScript, tapScript.ToHex())
			assert.Equal(t, expTopBranchHash, topBranchHash.ToHex(), testCase.CaseName)
			if _, ok := testCase.Expect["tweakedPubkey"]; ok {
				expTweakedPubkey := testCase.Expect["tweakedPubkey"].(string)
				expAddress := testCase.Expect["address"].(string)
				expLockingScript := testCase.Expect["lockingScript"].(string)
				assert.Equal(t, expAddress, address, testCase.CaseName)
				assert.Equal(t, expLockingScript, lockingScript)
				assert.Equal(t, expTweakedPubkey, tweakedPubkey.ToHex())

				var expTapLeafHash, expControlBlock string
				if _, ok := testCase.Expect["tapLeafHash"]; ok {
					expTapLeafHash = testCase.Expect["tapLeafHash"].(string)
					assert.Equal(t, expTapLeafHash, tapLeafHash.ToHex())
				}
				if _, ok := testCase.Expect["controlBlock"]; ok {
					expControlBlock = testCase.Expect["controlBlock"].(string)
					assert.Equal(t, expControlBlock, controlBlock.ToHex(), testCase.CaseName)
				}
			}
			if _, ok := testCase.Expect["tweakedPrivkey"]; ok {
				expTweakedPrivkey := testCase.Expect["tweakedPrivkey"].(string)
				assert.Equal(t, expTweakedPrivkey, tweakedPrivkey.ToHex())
			}

		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressGetTapScriptTreeInfoByControlBlock(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
			"request": {
					"network": "testnet",
					"isElements": false,
					"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
					"controlBlock": "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
					"internalPrivkey": "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27"
			},
			"expect": {
					"tapLeafHash": "dfc43ba9fc5f8a9e1b6d6a50600c704bb9e41b741d9ed6de6559a53d2f38e513",
					"topBranchHash": "09659d67a7a6fb82c1e382fd8f99f6bb43cbd80883845c6df7029f9589fc7af3",
					"tweakedPubkey": "3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"tweakedPrivkey": "a7d17bee0b6313cf864a1ac6f203aafd74a40703ffc050f66517e4f83ff41a03",
					"address": "tb1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fqekgu0q",
					"lockingScript": "51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"controlBlock": "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
					"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
					"nodes": [
							"4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
							"dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54"
					],
					"treeString": "{{4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)},dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54}"
			}
		*/

		tapscript := testCase.Request["tapscript"].(string)
		network := testCase.Request["network"].(string)
		networkType := types.NewNetworkTypeByString(network)
		controlBlock := testCase.Request["controlBlock"].(string)
		var internalPrivkey string
		if _, ok := testCase.Request["internalPrivkey"]; ok {
			internalPrivkey = testCase.Request["internalPrivkey"].(string)
		}

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		nodes := []string{}
		var tweakedPubkey, tweakedPrivkey, tapLeafHash, ctrlBlk *cfdgo.ByteData
		var address, lockingScript, treeString string
		branch, internalPubkey, err := cfdgo.NewTapBranchFromControlBlockWithNetwork(
			cfdgo.NewByteDataFromHexIgnoreError(controlBlock),
			cfdgo.NewScriptFromHexIgnoreError(tapscript), networkType.ToCfdValue())
		if err == nil {
			treeString = branch.GetTreeString()
			tweakedPubkey, tapLeafHash, ctrlBlk, err = branch.GetTweakedPubkey(internalPubkey)
		}
		if err == nil {
			nodes, err = branch.GetControlNodeList()
		}
		if err == nil {
			address, lockingScript, _, err = cfdgo.CfdGoCreateAddress(types.Taproot.ToCfdValue(), tweakedPubkey.ToHex(), "", networkType.ToCfdValue())
		}
		if err == nil && internalPrivkey != "" {
			tweakedPrivkey, err = branch.GetTweakedPrivkey(cfdgo.NewByteDataFromHexIgnoreError(internalPrivkey))
		}
		if _, ok := testCase.Expect["tweakedPubkey"]; ok {
			expTweakedPubkey := testCase.Expect["tweakedPubkey"].(string)
			expAddress := testCase.Expect["address"].(string)
			expLockingScript := testCase.Expect["lockingScript"].(string)
			expTapLeafHash := testCase.Expect["tapLeafHash"].(string)
			expTopBranchHash := testCase.Expect["topBranchHash"].(string)
			expTreeString := testCase.Expect["treeString"].(string)
			expTapscript := testCase.Expect["tapscript"].(string)
			expControlBlock := testCase.Expect["controlBlock"].(string)

			expNodes := make([]string, 0, len(nodes))
			if _, ok := testCase.Expect["nodes"]; ok {
				expNodesIF := testCase.Expect["nodes"].([]interface{})
				for i := range expNodesIF {
					expNodes = append(expNodes, expNodesIF[i].(string))
				}
			}

			assert.NoError(t, err, testCase.CaseName, branch)
			assert.Equal(t, expAddress, address)
			assert.Equal(t, expLockingScript, lockingScript)
			assert.Equal(t, expTweakedPubkey, tweakedPubkey.ToHex())
			assert.Equal(t, expTapLeafHash, tapLeafHash.ToHex())
			assert.Equal(t, expTopBranchHash, branch.Hash.ToHex())
			assert.Equal(t, expControlBlock, ctrlBlk.ToHex(), testCase.CaseName)
			assert.Equal(t, expTreeString, treeString)
			assert.Equal(t, expTapscript, branch.TapScript.ToHex())
			assert.Equal(t, expNodes, nodes)

			if tweakedPrivkey != nil {
				expTweakedPrivkey := testCase.Expect["tweakedPrivkey"].(string)
				assert.Equal(t, expTweakedPrivkey, tweakedPrivkey.ToHex())
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressGetTapScriptTreeFromString(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		/*
			"request": {
					"network": "mainnet",
					"isElements": false,
					"treeString": "{{4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)},dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54}",
					"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
					"internalPubkey": "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb"
			},
			"expect": {
					"tapLeafHash": "dfc43ba9fc5f8a9e1b6d6a50600c704bb9e41b741d9ed6de6559a53d2f38e513",
					"topBranchHash": "09659d67a7a6fb82c1e382fd8f99f6bb43cbd80883845c6df7029f9589fc7af3",
					"tweakedPubkey": "3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"address": "bc1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fqw77n40",
					"lockingScript": "51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
					"controlBlock": "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
					"tapscript": "201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
					"nodes": [
							"4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
							"dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54"
					],
					"treeString": "{{4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)},dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54}"
			}
		*/

		var tapscript string
		if _, ok := testCase.Request["tapscript"]; ok {
			tapscript = testCase.Request["tapscript"].(string)
		}
		treeString := testCase.Request["treeString"].(string)
		network := "mainnet"
		if _, ok := testCase.Request["network"]; ok {
			network = testCase.Request["network"].(string)
		}
		networkType := types.NewNetworkTypeByString(network)
		var internalPubkey string
		if _, ok := testCase.Request["internalPubkey"]; ok {
			internalPubkey = testCase.Request["internalPubkey"].(string)
		}
		var internalPrivkey string
		if _, ok := testCase.Request["internalPrivkey"]; ok {
			internalPrivkey = testCase.Request["internalPrivkey"].(string)
		}

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}
		inputNodes := make([]string, 0)
		if _, ok := testCase.Request["nodes"]; ok {
			inputNodesIF := testCase.Request["nodes"].([]interface{})
			for i := range inputNodesIF {
				inputNodes = append(inputNodes, inputNodesIF[i].(string))
			}

		}

		nodes := []string{}
		var tweakedPubkey, tweakedPrivkey, tapLeafHash, controlBlock *cfdgo.ByteData
		var address, lockingScript string
		branch, err := cfdgo.NewTapBranchFromStringByNodesWithNetwork(
			treeString, cfdgo.NewScriptFromHexIgnoreError(tapscript), inputNodes, networkType.ToCfdValue())
		if err == nil {
			treeString = branch.GetTreeString()
			nodes, err = branch.GetControlNodeList()
		}

		if err == nil {
			if internalPubkey != "" {
				tweakedPubkey, tapLeafHash, controlBlock, err = branch.GetTweakedPubkey(
					cfdgo.NewByteDataFromHexIgnoreError(internalPubkey))
			} else {
				tapLeafHash = &branch.TapLeafHash
			}
		}
		if err == nil && internalPubkey != "" {
			address, lockingScript, _, err = cfdgo.CfdGoCreateAddress(types.Taproot.ToCfdValue(), tweakedPubkey.ToHex(), "", networkType.ToCfdValue())
		}
		if err == nil && internalPrivkey != "" {
			tweakedPrivkey, err = branch.GetTweakedPrivkey(cfdgo.NewByteDataFromHexIgnoreError(internalPrivkey))
		}
		if _, ok := testCase.Expect["treeString"]; ok {
			var expTweakedPubkey, expAddress, expTapLeafHash, expTapscript string
			var expLockingScript, expTopBranchHash, expControlBlock string
			expTreeString := testCase.Expect["treeString"].(string)
			if _, ok := testCase.Expect["lockingScript"]; ok {
				expLockingScript = testCase.Expect["lockingScript"].(string)
			}
			if _, ok := testCase.Expect["topBranchHash"]; ok {
				expTopBranchHash = testCase.Expect["topBranchHash"].(string)
			}
			if _, ok := testCase.Expect["tweakedPubkey"]; ok {
				expTweakedPubkey = testCase.Expect["tweakedPubkey"].(string)
			}
			if _, ok := testCase.Expect["address"]; ok {
				expAddress = testCase.Expect["address"].(string)
			}
			if _, ok := testCase.Expect["tapLeafHash"]; ok {
				expTapLeafHash = testCase.Expect["tapLeafHash"].(string)
			}
			if _, ok := testCase.Expect["tapscript"]; ok {
				expTapscript = testCase.Expect["tapscript"].(string)
			}
			if _, ok := testCase.Expect["controlBlock"]; ok {
				expControlBlock = testCase.Expect["controlBlock"].(string)
			}

			expNodes := make([]string, 0, len(nodes))
			if _, ok := testCase.Expect["nodes"]; ok {
				expNodesIF := testCase.Expect["nodes"].([]interface{})
				for i := range expNodesIF {
					expNodes = append(expNodes, expNodesIF[i].(string))
				}
			}

			assert.NoError(t, err, testCase.CaseName)
			assert.Equal(t, expAddress, address, testCase.CaseName)
			assert.Equal(t, expLockingScript, lockingScript, testCase.CaseName)
			assert.Equal(t, expTweakedPubkey, tweakedPubkey.ToHex(), testCase.CaseName)
			assert.Equal(t, expTapLeafHash, tapLeafHash.ToHex(), testCase.CaseName)
			assert.Equal(t, expTopBranchHash, branch.Hash.ToHex(), testCase.CaseName)
			assert.Equal(t, expTreeString, treeString, testCase.CaseName)
			if expControlBlock != "" {
				assert.Equal(t, expControlBlock, controlBlock.ToHex(), testCase.CaseName)
			}
			if expTapscript != "" && len(expNodes) > 0 {
				assert.Equal(t, expTapscript, branch.TapScript.ToHex(), testCase.CaseName)
				assert.Equal(t, expNodes, nodes, testCase.CaseName)
			}

			if tweakedPrivkey != nil {
				expTweakedPrivkey := testCase.Expect["tweakedPrivkey"].(string)
				assert.Equal(t, expTweakedPrivkey, tweakedPrivkey.ToHex())
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

func testAddressGetTapBranchInfo(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		// FIXME: 実装する
		/*
			"request": {
				"network": "liquidv1",
				"isElements": true,
				"treeString": "{{{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}},{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}},tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)}",
				"tapscript": "51",
				"nodes": [
						"aec3ae4c22421c8e0cc7aeb4c34a247eae16772ab0ad7afaad92850a890af55c",
						"e027953fb3c0bfc45b32d5729b9b130113e40354b6bf7a41da74983e4dd67aec",
						"a68004de62a29dd603d8cb9070a190df4fa1fc726b7cce846ea3f540c51ebc22"
				],
				"index": 1
			},
			"expect": {
				"topBranchHash": "e027953fb3c0bfc45b32d5729b9b130113e40354b6bf7a41da74983e4dd67aec",
				"nodes": [
						"1b493a6f3185a4ad847dbdc2216e69212380b315f7191d946dcb153a60446f6c",
						"8a5c6e74080fe957d9140c7c063fc68b70b9972ccccf4b4a1372ab8272119567"
				],
				"treeString": "{{{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)},tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac)},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}"
			}
		*/

		treeString := testCase.Request["treeString"].(string)
		index := uint8(testCase.Request["index"].(float64))
		var nodes []string
		if _, ok := testCase.Request["nodes"]; ok {
			nodesIF := testCase.Request["nodes"].([]interface{})
			nodes = make([]string, len(nodesIF))
			for i := range nodesIF {
				nodes[i] = nodesIF[i].(string)
			}
		}
		network := "mainnet"
		if _, ok := testCase.Request["network"]; ok {
			network = testCase.Request["network"].(string)
		}
		networkType := types.NewNetworkTypeByString(network)
		var tapscript *cfdgo.Script
		if _, ok := testCase.Request["tapscript"]; ok {
			tapscript = cfdgo.NewScriptFromHexIgnoreError(testCase.Request["tapscript"].(string))
		}

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		branch, err := cfdgo.NewTapBranchFromStringByNodesWithNetwork(
			treeString, tapscript, nodes, networkType.ToCfdValue())
		if err == nil {
			branch, err = branch.GetBranch(index)
		}
		if _, ok := testCase.Expect["treeString"]; ok {
			assert.NoError(t, err)

			expTopBranchHash := testCase.Expect["topBranchHash"].(string)
			expTreeString := testCase.Expect["treeString"].(string)

			if branch != nil {
				childTreeStr := branch.GetTreeString()
				assert.Equal(t, expTopBranchHash, branch.Hash.ToHex())
				assert.Equal(t, expTreeString, childTreeStr, testCase.CaseName, branch)

				// FIXME: There may be some problem with the sort order on the library side.
				/*
					childNodes, err := branch.GetControlNodeList()
					assert.NoError(t, err)
					expNodes := make([]string, 0, len(nodes))
					if _, ok := testCase.Expect["nodes"]; ok {
						expNodesIF := testCase.Expect["nodes"].([]interface{})
						for i := range expNodesIF {
							expNodes = append(expNodes, expNodesIF[i].(string))
						}
					}
					assert.Equal(t, expNodes, childNodes, testCase.CaseName, branch)
				*/
			}
		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}

/* FIXME: please implement after
func testAddressAnalyzeTapScriptTree(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}
		// "request": {
		// 		"network": "liquidv1",
		// 		"isElements": true,
		// 		"treeString": "{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),tl(51)},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}"
		// },
		// "expect": {
		// 		"branches": [
		// 				{
		// 						"depth": 2,
		// 						"tapBranchHash": "4e6fe964c9dcdef0659936b3fceb4f79f8d764d979fe65452f4d55bf06fddc59",
		// 						"tapscript": "20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac",
		// 						"leafVersion": 196
		// 				},
		// 				{
		// 						"depth": 1,
		// 						"tapBranchHash": "ff556c786e5e3968e7e162a90a2afb042db4d342a453730c750ba0f0f578dbb4",
		// 						"relatedBranchHash": [
		// 								"4e6fe964c9dcdef0659936b3fceb4f79f8d764d979fe65452f4d55bf06fddc59",
		// 								"a81c7f30802409528d2d0ac880b8072c97e96c303f4759707394af544fc3df40"
		// 						]
		// 				},
		// 				{
		// 						"depth": 2,
		// 						"tapBranchHash": "a81c7f30802409528d2d0ac880b8072c97e96c303f4759707394af544fc3df40",
		// 						"tapscript": "51",
		// 						"leafVersion": 196
		// 				},
		// 				{
		// 						"depth": 0,
		// 						"tapBranchHash": "56df52b4c09031a69b140719685091063f4090a9327a61b19985fa5cf65a0c88",
		// 						"relatedBranchHash": [
		// 								"ff556c786e5e3968e7e162a90a2afb042db4d342a453730c750ba0f0f578dbb4",
		// 								"8a5c6e74080fe957d9140c7c063fc68b70b9972ccccf4b4a1372ab8272119567"
		// 						]
		// 				},
		// 				{
		// 						"depth": 1,
		// 						"tapBranchHash": "8a5c6e74080fe957d9140c7c063fc68b70b9972ccccf4b4a1372ab8272119567",
		// 						"tapscript": "2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac",
		// 						"leafVersion": 196
		// 				}
		// 		]
		// }

		network := testCase.Request["network"].(string)
		treeString := testCase.Request["treeString"].(string)
		networkType := types.NewNetworkTypeByString(network)

		var isElements bool
		if _, ok := testCase.Request["isElements"]; ok {
			isElements = testCase.Request["isElements"].(bool)
		}
		if networkType.IsBitcoin() && isElements {
			switch networkType {
			case types.Mainnet:
				networkType = types.LiquidV1
			case types.Regtest, types.Testnet:
				networkType = types.ElementsRegtest
			}
		}

		branch, err := cfdgo.NewTapBranchFromStringWithNetwork(treeString, nil, networkType.ToCfdValue())
		if _, ok := testCase.Expect["address"]; ok {
			expAddress := testCase.Expect["address"].(string)
			expLockingScript := testCase.Expect["lockingScript"].(string)

			assert.NoError(t, err)
			assert.Equal(t, expAddress, branch.Hash.ToHex())
			assert.Equal(t, expLockingScript, branch.Hash.ToHex())

		} else {
			assert.Error(t, err)
			expErr := testCase.ErrorData.GetErrorString()
			if err == nil {
				panic(fmt.Sprintf("error not match, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			if expErr == "" {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
			assert.Equal(t, true, strings.Contains(err.Error(), expErr))
			if !strings.Contains(err.Error(), expErr) {
				panic(fmt.Sprintf("empty error data, test:%s, case:%s, err:%v", testData.Name, testCase.CaseName, err))
			}
		}
		count++
		waitForTest()
	}

	fmt.Printf("%s test done. count:%d\n", GetFuncName(), count)
}
*/
