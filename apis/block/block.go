package block

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	types "github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// API struct
// -------------------------------------

type BlockApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *BlockApiImpl, err error)
	GetHeaderData(block *types.Block) (blockHash string, header *types.BlockHeader, err error)
	GetTxCount(block *types.Block) (count uint32, err error)
	GetTxidList(block *types.Block) (txidList []string, err error)
	GetTransactionData(block *types.Block, txid string) (tx *types.Transaction, txoutProof *types.ByteData, err error)
	ExistTxid(block *types.Block, txid string) (exist bool, err error)
}

func NewBlockApi() *BlockApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := BlockApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

// -------------------------------------
// BlockApiImpl
// -------------------------------------

// BlockApiImpl The bitcoin block utility.
type BlockApiImpl struct {
	network *types.NetworkType
}

// WithConfig This function set a configuration.
func (p *BlockApiImpl) WithConfig(conf config.CfdConfig) (obj *BlockApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

// GetHeaderData ...
func (b *BlockApiImpl) GetHeaderData(block *types.Block) (blockHash string, header *types.BlockHeader, err error) {
	if err = b.validConfig(); err != nil {
		return "", nil, err
	}
	hash, cfdHeader, err := cfd.CfdGoGetBlockHeaderData(b.network.ToCfdValue(), block.Hex)
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
func (b *BlockApiImpl) GetTxCount(block *types.Block) (count uint32, err error) {
	if err = b.validConfig(); err != nil {
		return 0, err
	}
	return cfd.CfdGoGetTxCountInBlock(b.network.ToCfdValue(), block.Hex)
}

// GetTxidList ...
func (b *BlockApiImpl) GetTxidList(block *types.Block) (txidList []string, err error) {
	if err = b.validConfig(); err != nil {
		return nil, err
	}
	return cfd.CfdGoGetTxidListFromBlock(b.network.ToCfdValue(), block.Hex)
}

// GetTransactionData ...
func (b *BlockApiImpl) GetTransactionData(block *types.Block, txid string) (tx *types.Transaction, txoutProof *types.ByteData, err error) {
	if err = b.validConfig(); err != nil {
		return nil, nil, err
	}
	txHex, proof, err := cfd.CfdGoGetTransactionDataFromBlock(b.network.ToCfdValue(), block.Hex, txid)
	if err != nil {
		return nil, nil, err
	}
	tx = &types.Transaction{Hex: txHex}
	txoutProof = types.NewByteDataFromHexIgnoreError(proof)
	return tx, txoutProof, nil
}

// ExistTxid ...
func (b *BlockApiImpl) ExistTxid(block *types.Block, txid string) (exist bool, err error) {
	if err = b.validConfig(); err != nil {
		return false, err
	}
	return cfd.CfdGoExistTxidInBlock(b.network.ToCfdValue(), block.Hex, txid)
}

// validConfig ...
func (b *BlockApiImpl) validConfig() error {
	if b.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	} else if !b.network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
	}
	return nil
}
