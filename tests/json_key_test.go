package tests

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"testing"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	jsonData := readFile(path.Join(".", "data", "key_test.json"))

	testDataArr := []JsonTestData{}
	if err := json.Unmarshal(jsonData, &testDataArr); err != nil {
		panic(err)
	}
	for _, testData := range testDataArr {
		switch testData.Name {
		case "Privkey.SignMessage":
			testSignMessage(t, &testData)
		case "Pubkey.VerifyMessage":
			testVerifyMessage(t, &testData)
		default:
			// FIXME: not implements
		}
	}
	fmt.Printf("%s test done.\n", GetFuncName())
}

func testSignMessage(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		privkey := testCase.Request["privkey"].(string)
		message := testCase.Request["message"].(string)
		signature, err := cfdgo.CfdGoSignMessage(privkey, message, "", false)
		base64, err2 := cfdgo.CfdGoSignMessage(privkey, message, "", true)
		if _, ok := testCase.Expect["signature"]; ok {
			expSignature := testCase.Expect["signature"].(string)
			expBase64 := testCase.Expect["base64"].(string)
			assert.NoError(t, err)
			assert.NoError(t, err2)
			assert.Equal(t, expSignature, signature)
			assert.Equal(t, expBase64, base64)
		} else {
			assert.Error(t, err)
			assert.Error(t, err2)
			assert.Equal(t, err, err2)
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

func testVerifyMessage(t *testing.T, testData *JsonTestData) {
	var count int
	for _, testCase := range testData.Cases {
		if testCase.HasSkip() {
			continue
		}

		signature := testCase.Request["signature"].(string)
		pubkey := testCase.Request["pubkey"].(string)
		message := testCase.Request["message"].(string)
		magic := testCase.Request["magic"].(string)
		// ignoreError := testCase.Request["ignoreError"].(bool)
		recoveredPubkey, isVerify, err := cfdgo.CfdGoVerifyMessage(signature, pubkey, message, magic)
		if _, ok := testCase.Expect["success"]; ok {
			expSuccess := testCase.Expect["success"].(bool)
			expPubkey := testCase.Expect["pubkey"].(string)
			assert.NoError(t, err)
			assert.Equal(t, expSuccess, isVerify)
			assert.Equal(t, expPubkey, recoveredPubkey)
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
