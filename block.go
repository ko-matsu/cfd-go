package cfdgo

import (
	"fmt"
	"unsafe"
)

// -------------------------------------
// API struct
// -------------------------------------

// Block The bitcoin block.
type Block struct {
	Hex     string
	Network *NetworkType
}

// -------------------------------------
// Data struct
// -------------------------------------

// BlockHeader block header information.
type BlockHeader struct {
	Version       uint32 // Version
	PrevBlockHash string // previous block hash
	MerkleRoot    string // merkleroot
	Time          uint32 // block time
	Bits          uint32 // bit flag
	Nonce         uint32 // nonce
}

// -------------------------------------
// Block
// -------------------------------------

// GetBlockHeaderData ...
func (b *Block) GetHeaderData() (blockHash string, header *BlockHeader, err error) {
	if err = b.validConfig(); err != nil {
		return "", nil, err
	}
	return CfdGoGetBlockHeaderData(b.Network.ToCfdValue(), b.Hex)
}

// GetTxCountInBlock ...
func (b *Block) GetTxCount() (count uint32, err error) {
	if err = b.validConfig(); err != nil {
		return 0, err
	}
	return CfdGoGetTxCountInBlock(b.Network.ToCfdValue(), b.Hex)
}

// GetTxidListFromBlock ...
func (b *Block) GetTxidList() (txidList []string, err error) {
	if err = b.validConfig(); err != nil {
		return nil, err
	}
	return CfdGoGetTxidListFromBlock(b.Network.ToCfdValue(), b.Hex)
}

// GetTransactionDataFromBlock ...
func (b *Block) GetTransactionData(txid string) (tx *Transaction, txoutProof *ByteData, err error) {
	if err = b.validConfig(); err != nil {
		return nil, nil, err
	}
	txHex, proof, err := CfdGoGetTransactionDataFromBlock(b.Network.ToCfdValue(), b.Hex, txid)
	if err != nil {
		return nil, nil, err
	}
	tx = &Transaction{Hex: txHex, Network: *b.Network}
	txoutProof = NewByteDataFromHexIgnoreError(proof)
	return tx, txoutProof, nil
}

// ExistTxidInBlock ...
func (b *Block) ExistTxid(txid string) (exist bool, err error) {
	if err = b.validConfig(); err != nil {
		return false, err
	}
	return CfdGoExistTxidInBlock(b.Network.ToCfdValue(), b.Hex, txid)
}

// validConfig ...
func (b *Block) validConfig() error {
	if b.Network == nil {
		if !cfdConfig.Network.Valid() {
			return fmt.Errorf("CFD Error: NetworkType not set")
		}
		if cfdConfig.Network.IsElements() {
			netType := cfdConfig.Network.ToBitcoinType()
			b.Network = &netType
		} else {
			netType := cfdConfig.Network
			b.Network = &netType
		}
	}
	if !b.Network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}

// low-layer API ---------------------------------------------------------------

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

// GetTxCountInBlock This function get a trasaction count in this block.
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
