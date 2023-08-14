// Code generated by MockGen. DO NOT EDIT.
// Source: pegout.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	types "github.com/cryptogarageinc/cfd-go/types"
	gomock "go.uber.org/mock/gomock"
)

// MockPegout is a mock of Pegout interface.
type MockPegout struct {
	ctrl     *gomock.Controller
	recorder *MockPegoutMockRecorder
}

// MockPegoutMockRecorder is the mock recorder for MockPegout.
type MockPegoutMockRecorder struct {
	mock *MockPegout
}

// NewMockPegout creates a new mock instance.
func NewMockPegout(ctrl *gomock.Controller) *MockPegout {
	mock := &MockPegout{ctrl: ctrl}
	mock.recorder = &MockPegoutMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPegout) EXPECT() *MockPegoutMockRecorder {
	return m.recorder
}

// ContainsPakEntry mocks base method.
func (m *MockPegout) ContainsPakEntry(pakEntry *types.ByteData, whitelist string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainsPakEntry", pakEntry, whitelist)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainsPakEntry indicates an expected call of ContainsPakEntry.
func (mr *MockPegoutMockRecorder) ContainsPakEntry(pakEntry, whitelist interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainsPakEntry", reflect.TypeOf((*MockPegout)(nil).ContainsPakEntry), pakEntry, whitelist)
}

// CreateOnlinePrivateKey mocks base method.
func (m *MockPegout) CreateOnlinePrivateKey() (*types.Privkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateOnlinePrivateKey")
	ret0, _ := ret[0].(*types.Privkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateOnlinePrivateKey indicates an expected call of CreateOnlinePrivateKey.
func (mr *MockPegoutMockRecorder) CreateOnlinePrivateKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateOnlinePrivateKey", reflect.TypeOf((*MockPegout)(nil).CreateOnlinePrivateKey))
}

// CreatePakEntry mocks base method.
func (m *MockPegout) CreatePakEntry(accountExtPubkey *types.ExtPubkey, onlinePrivkey *types.Privkey) (*types.PakEntry, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePakEntry", accountExtPubkey, onlinePrivkey)
	ret0, _ := ret[0].(*types.PakEntry)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePakEntry indicates an expected call of CreatePakEntry.
func (mr *MockPegoutMockRecorder) CreatePakEntry(accountExtPubkey, onlinePrivkey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePakEntry", reflect.TypeOf((*MockPegout)(nil).CreatePakEntry), accountExtPubkey, onlinePrivkey)
}

// CreatePegoutAddress mocks base method.
func (m *MockPegout) CreatePegoutAddress(addressType types.AddressType, accountExtPubkey *types.ExtPubkey, addressIndex uint32) (*types.Address, *types.Descriptor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePegoutAddress", addressType, accountExtPubkey, addressIndex)
	ret0, _ := ret[0].(*types.Address)
	ret1, _ := ret[1].(*types.Descriptor)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreatePegoutAddress indicates an expected call of CreatePegoutAddress.
func (mr *MockPegoutMockRecorder) CreatePegoutAddress(addressType, accountExtPubkey, addressIndex interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePegoutAddress", reflect.TypeOf((*MockPegout)(nil).CreatePegoutAddress), addressType, accountExtPubkey, addressIndex)
}

// CreatePegoutTransaction mocks base method.
func (m *MockPegout) CreatePegoutTransaction(utxoList []*types.ElementsUtxoData, pegoutData types.InputConfidentialTxOut, sendList []*types.InputConfidentialTxOut, changeAddress *string, option *types.PegoutTxOption) (*types.ConfidentialTx, *types.Address, *types.ConfidentialTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePegoutTransaction", utxoList, pegoutData, sendList, changeAddress, option)
	ret0, _ := ret[0].(*types.ConfidentialTx)
	ret1, _ := ret[1].(*types.Address)
	ret2, _ := ret[2].(*types.ConfidentialTx)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// CreatePegoutTransaction indicates an expected call of CreatePegoutTransaction.
func (mr *MockPegoutMockRecorder) CreatePegoutTransaction(utxoList, pegoutData, sendList, changeAddress, option interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePegoutTransaction", reflect.TypeOf((*MockPegout)(nil).CreatePegoutTransaction), utxoList, pegoutData, sendList, changeAddress, option)
}

// VerifyPubkeySignature mocks base method.
func (m *MockPegout) VerifyPubkeySignature(proposalTx *types.ConfidentialTx, utxoData *types.ElementsUtxoData, signature *types.ByteData) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyPubkeySignature", proposalTx, utxoData, signature)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyPubkeySignature indicates an expected call of VerifyPubkeySignature.
func (mr *MockPegoutMockRecorder) VerifyPubkeySignature(proposalTx, utxoData, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyPubkeySignature", reflect.TypeOf((*MockPegout)(nil).VerifyPubkeySignature), proposalTx, utxoData, signature)
}
