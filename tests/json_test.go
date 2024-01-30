package tests

import (
	"os"
	"path"
)

type ErrorData struct {
	MessageError string `json:"message"`
	CfdError     string `json:"cfd"`
	CApiError    string `json:"capi"`
	JsonError    string `json:"json"`
	GoError      string `json:"go"`
}

func (e ErrorData) GetErrorString() string {
	if e.GoError != "" {
		return e.GoError
	} else if e.CApiError != "" {
		return e.CApiError
	} else if e.CfdError != "" {
		return e.CfdError
	} else if e.MessageError != "" {
		return e.MessageError
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
		if exclude == "go" || exclude == "capi" {
			return true
		}
	}
	return false
}

type JsonTestData struct {
	Name  string         `json:"name"`
	Cases []TestCaseData `json:"cases"`
}

func waitForTest() {
	//time.Sleep(100 * time.Millisecond)
}

func readFile(fileName string) []byte {
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		bytes, err = os.ReadFile(path.Join(".", "tests", fileName))
		if err != nil {
			panic(err)
		}
	}
	return bytes
}
