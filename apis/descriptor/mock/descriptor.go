// Code generated by MockGen. DO NOT EDIT.
// Source: descriptor.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	types "github.com/cryptogarageinc/cfd-go/types"
	gomock "github.com/golang/mock/gomock"
)

// MockDescriptorApi is a mock of DescriptorApi interface.
type MockDescriptorApi struct {
	ctrl     *gomock.Controller
	recorder *MockDescriptorApiMockRecorder
}

// MockDescriptorApiMockRecorder is the mock recorder for MockDescriptorApi.
type MockDescriptorApiMockRecorder struct {
	mock *MockDescriptorApi
}

// NewMockDescriptorApi creates a new mock instance.
func NewMockDescriptorApi(ctrl *gomock.Controller) *MockDescriptorApi {
	mock := &MockDescriptorApi{ctrl: ctrl}
	mock.recorder = &MockDescriptorApiMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDescriptorApi) EXPECT() *MockDescriptorApiMockRecorder {
	return m.recorder
}

// GetChecksum mocks base method.
func (m *MockDescriptorApi) GetChecksum(descriptor *types.Descriptor) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetChecksum", descriptor)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetChecksum indicates an expected call of GetChecksum.
func (mr *MockDescriptorApiMockRecorder) GetChecksum(descriptor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetChecksum", reflect.TypeOf((*MockDescriptorApi)(nil).GetChecksum), descriptor)
}

// GetNetworkTypes mocks base method.
func (m *MockDescriptorApi) GetNetworkTypes() []types.NetworkType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkTypes")
	ret0, _ := ret[0].([]types.NetworkType)
	return ret0
}

// GetNetworkTypes indicates an expected call of GetNetworkTypes.
func (mr *MockDescriptorApiMockRecorder) GetNetworkTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkTypes", reflect.TypeOf((*MockDescriptorApi)(nil).GetNetworkTypes))
}

// NewDescriptorFromAddress mocks base method.
func (m *MockDescriptorApi) NewDescriptorFromAddress(address string) *types.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDescriptorFromAddress", address)
	ret0, _ := ret[0].(*types.Descriptor)
	return ret0
}

// NewDescriptorFromAddress indicates an expected call of NewDescriptorFromAddress.
func (mr *MockDescriptorApiMockRecorder) NewDescriptorFromAddress(address interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDescriptorFromAddress", reflect.TypeOf((*MockDescriptorApi)(nil).NewDescriptorFromAddress), address)
}

// NewDescriptorFromLockingScript mocks base method.
func (m *MockDescriptorApi) NewDescriptorFromLockingScript(lockingScript string) *types.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDescriptorFromLockingScript", lockingScript)
	ret0, _ := ret[0].(*types.Descriptor)
	return ret0
}

// NewDescriptorFromLockingScript indicates an expected call of NewDescriptorFromLockingScript.
func (mr *MockDescriptorApiMockRecorder) NewDescriptorFromLockingScript(lockingScript interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDescriptorFromLockingScript", reflect.TypeOf((*MockDescriptorApi)(nil).NewDescriptorFromLockingScript), lockingScript)
}

// NewDescriptorFromMultisig mocks base method.
func (m *MockDescriptorApi) NewDescriptorFromMultisig(hashType types.HashType, pubkeys []string, requireNum int) *types.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDescriptorFromMultisig", hashType, pubkeys, requireNum)
	ret0, _ := ret[0].(*types.Descriptor)
	return ret0
}

// NewDescriptorFromMultisig indicates an expected call of NewDescriptorFromMultisig.
func (mr *MockDescriptorApiMockRecorder) NewDescriptorFromMultisig(hashType, pubkeys, requireNum interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDescriptorFromMultisig", reflect.TypeOf((*MockDescriptorApi)(nil).NewDescriptorFromMultisig), hashType, pubkeys, requireNum)
}

// NewDescriptorFromPubkey mocks base method.
func (m *MockDescriptorApi) NewDescriptorFromPubkey(hashType types.HashType, pubkey *types.Pubkey) *types.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDescriptorFromPubkey", hashType, pubkey)
	ret0, _ := ret[0].(*types.Descriptor)
	return ret0
}

// NewDescriptorFromPubkey indicates an expected call of NewDescriptorFromPubkey.
func (mr *MockDescriptorApiMockRecorder) NewDescriptorFromPubkey(hashType, pubkey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDescriptorFromPubkey", reflect.TypeOf((*MockDescriptorApi)(nil).NewDescriptorFromPubkey), hashType, pubkey)
}

// NewDescriptorFromString mocks base method.
func (m *MockDescriptorApi) NewDescriptorFromString(descriptor string) *types.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDescriptorFromString", descriptor)
	ret0, _ := ret[0].(*types.Descriptor)
	return ret0
}

// NewDescriptorFromString indicates an expected call of NewDescriptorFromString.
func (mr *MockDescriptorApiMockRecorder) NewDescriptorFromString(descriptor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDescriptorFromString", reflect.TypeOf((*MockDescriptorApi)(nil).NewDescriptorFromString), descriptor)
}

// Parse mocks base method.
func (m *MockDescriptorApi) Parse(descriptor *types.Descriptor) (*types.DescriptorRootData, []types.DescriptorData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Parse", descriptor)
	ret0, _ := ret[0].(*types.DescriptorRootData)
	ret1, _ := ret[1].([]types.DescriptorData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Parse indicates an expected call of Parse.
func (mr *MockDescriptorApiMockRecorder) Parse(descriptor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Parse", reflect.TypeOf((*MockDescriptorApi)(nil).Parse), descriptor)
}

// ParseByFilter mocks base method.
func (m *MockDescriptorApi) ParseByFilter(descriptor *types.Descriptor, filter *types.DescriptorParseFilter) (*types.DescriptorRootData, []types.DescriptorData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseByFilter", descriptor, filter)
	ret0, _ := ret[0].(*types.DescriptorRootData)
	ret1, _ := ret[1].([]types.DescriptorData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ParseByFilter indicates an expected call of ParseByFilter.
func (mr *MockDescriptorApiMockRecorder) ParseByFilter(descriptor, filter interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseByFilter", reflect.TypeOf((*MockDescriptorApi)(nil).ParseByFilter), descriptor, filter)
}

// ParseByFilterWithDerivationPath mocks base method.
func (m *MockDescriptorApi) ParseByFilterWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string, filter *types.DescriptorParseFilter) (*types.DescriptorRootData, []types.DescriptorData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseByFilterWithDerivationPath", descriptor, bip32DerivationPath, filter)
	ret0, _ := ret[0].(*types.DescriptorRootData)
	ret1, _ := ret[1].([]types.DescriptorData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ParseByFilterWithDerivationPath indicates an expected call of ParseByFilterWithDerivationPath.
func (mr *MockDescriptorApiMockRecorder) ParseByFilterWithDerivationPath(descriptor, bip32DerivationPath, filter interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseByFilterWithDerivationPath", reflect.TypeOf((*MockDescriptorApi)(nil).ParseByFilterWithDerivationPath), descriptor, bip32DerivationPath, filter)
}

// ParseByString mocks base method.
func (m *MockDescriptorApi) ParseByString(descriptor string) (*types.DescriptorRootData, []types.DescriptorData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseByString", descriptor)
	ret0, _ := ret[0].(*types.DescriptorRootData)
	ret1, _ := ret[1].([]types.DescriptorData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ParseByString indicates an expected call of ParseByString.
func (mr *MockDescriptorApiMockRecorder) ParseByString(descriptor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseByString", reflect.TypeOf((*MockDescriptorApi)(nil).ParseByString), descriptor)
}

// ParseWithDerivationPath mocks base method.
func (m *MockDescriptorApi) ParseWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string) (*types.DescriptorRootData, []types.DescriptorData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseWithDerivationPath", descriptor, bip32DerivationPath)
	ret0, _ := ret[0].(*types.DescriptorRootData)
	ret1, _ := ret[1].([]types.DescriptorData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ParseWithDerivationPath indicates an expected call of ParseWithDerivationPath.
func (mr *MockDescriptorApiMockRecorder) ParseWithDerivationPath(descriptor, bip32DerivationPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseWithDerivationPath", reflect.TypeOf((*MockDescriptorApi)(nil).ParseWithDerivationPath), descriptor, bip32DerivationPath)
}
