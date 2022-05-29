package tests

import (
	"io/ioutil"
)

type ErrorData struct {
	CfdError  string `json:"cfd"`
	CApiError string `json:"capi"`
	JsonError string `json:"json"`
	GoError   string `json:"go"`
}

func (e ErrorData) GetErrorString() string {
	if e.GoError != "" {
		return e.GoError
	} else if e.CApiError != "" {
		return e.CApiError
	} else if e.CfdError != "" {
		return e.CfdError
	}
	return ""
}

type TestCaseData struct {
	CaseName  string                 `json:"case"`
	Request   map[string]interface{} `json:"request"`
	Expect    map[string]interface{} `json:"expect"`
	ErrorData ErrorData              `json:"error"`
	Excludes  []string               `json:"exclude"`
}

func (t TestCaseData) HasSkip() bool {
	for _, exclude := range t.Excludes {
		if exclude == "go" {
			return true
		}
	}
	return false
}

type JsonTestData struct {
	Name  string         `json:"name"`
	Cases []TestCaseData `json:"cases"`
}

func readFile(fileName string) []byte {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	return bytes
}
