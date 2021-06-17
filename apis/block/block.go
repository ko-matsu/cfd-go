package block

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	config "github.com/cryptogarageinc/cfd-go/config"
	types "github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// API struct
// -------------------------------------

type BlockApi interface {
	GetHeaderData(block *types.Block) (blockHash string, header *types.BlockHeader, err error)
	GetTxCount(block *types.Block) (count uint32, err error)
	GetTxidList(block *types.Block) (txidList []string, err error)
	GetTransactionData(block *types.Block, txid string) (tx *types.Transaction, txoutProof *types.ByteData, err error)
	ExistTxid(block *types.Block, txid string) (exist bool, err error)
}

func NewBlockApi() BlockApi {
	return &BlockUtil{}
}

// -------------------------------------
// BlockUtil
// -------------------------------------

// BlockUtil The bitcoin block utility.
type BlockUtil struct {
	Network *types.NetworkType
}

// GetHeaderData ...
func (b *BlockUtil) GetHeaderData(block *types.Block) (blockHash string, header *types.BlockHeader, err error) {
	if err = b.validConfig(); err != nil {
		return "", nil, err
	}
	hash, cfdHeader, err := cfd.CfdGoGetBlockHeaderData(b.Network.ToCfdValue(), block.Hex)
	if err != nil {
		return "", nil, err
	}
	return hash, &types.BlockHeader{
		Version:       cfdHeader.Version,
		PrevBlockHash: cfdHeader.PrevBlockHash,
		MerkleRoot:    cfdHeader.MerkleRoot,
		Time:          cfdHeader.Time,
		Bits:          cfdHeader.Bits,
		Nonce:         cfdHeader.Nonce,
	}, nil
}

// GetTxCount ...
func (b *BlockUtil) GetTxCount(block *types.Block) (count uint32, err error) {
	if err = b.validConfig(); err != nil {
		return 0, err
	}
	return cfd.CfdGoGetTxCountInBlock(b.Network.ToCfdValue(), block.Hex)
}

// GetTxidList ...
func (b *BlockUtil) GetTxidList(block *types.Block) (txidList []string, err error) {
	if err = b.validConfig(); err != nil {
		return nil, err
	}
	return cfd.CfdGoGetTxidListFromBlock(b.Network.ToCfdValue(), block.Hex)
}

// GetTransactionData ...
func (b *BlockUtil) GetTransactionData(block *types.Block, txid string) (tx *types.Transaction, txoutProof *types.ByteData, err error) {
	if err = b.validConfig(); err != nil {
		return nil, nil, err
	}
	txHex, proof, err := cfd.CfdGoGetTransactionDataFromBlock(b.Network.ToCfdValue(), block.Hex, txid)
	if err != nil {
		return nil, nil, err
	}
	tx = &types.Transaction{Hex: txHex}
	txoutProof = types.NewByteDataFromHexIgnoreError(proof)
	return tx, txoutProof, nil
}

// ExistTxid ...
func (b *BlockUtil) ExistTxid(block *types.Block, txid string) (exist bool, err error) {
	if err = b.validConfig(); err != nil {
		return false, err
	}
	return cfd.CfdGoExistTxidInBlock(b.Network.ToCfdValue(), block.Hex, txid)
}

// validConfig ...
func (b *BlockUtil) validConfig() error {
	if b.Network == nil {
		cfdConfig := config.GetCurrentCfdConfig()
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
