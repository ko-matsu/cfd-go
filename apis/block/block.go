package block

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
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
		return p, cfdErrors.NetworkConfigError
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	obj = p
	return obj, nil
}

// GetHeaderData ...
func (b *BlockApiImpl) GetHeaderData(block *types.Block) (blockHash string, header *types.BlockHeader, err error) {
	if err = b.validConfig(); err != nil {
		return "", nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	hash, cfdHeader, err := cfd.CfdGoGetBlockHeaderData(b.network.ToCfdValue(), block.Hex)
	if err != nil {
		return "", nil, errors.Wrap(err, "get block data error")
	}
	header = &types.BlockHeader{
		Version:       cfdHeader.Version,
		PrevBlockHash: cfdHeader.PrevBlockHash,
		MerkleRoot:    cfdHeader.MerkleRoot,
		Time:          cfdHeader.Time,
		Bits:          cfdHeader.Bits,
		Nonce:         cfdHeader.Nonce,
	}
	return hash, header, nil
}

// GetTxCount ...
func (b *BlockApiImpl) GetTxCount(block *types.Block) (count uint32, err error) {
	if err = b.validConfig(); err != nil {
		return 0, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if count, err = cfd.CfdGoGetTxCountInBlock(b.network.ToCfdValue(), block.Hex); err != nil {
		return 0, errors.Wrap(err, "get block tx count error")
	}
	return count, nil
}

// GetTxidList ...
func (b *BlockApiImpl) GetTxidList(block *types.Block) (txidList []string, err error) {
	if err = b.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if txidList, err = cfd.CfdGoGetTxidListFromBlock(b.network.ToCfdValue(), block.Hex); err != nil {
		return nil, errors.Wrap(err, "get block txids error")
	}
	return txidList, nil
}

// GetTransactionData ...
func (b *BlockApiImpl) GetTransactionData(block *types.Block, txid string) (tx *types.Transaction, txoutProof *types.ByteData, err error) {
	if err = b.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	txHex, proof, err := cfd.CfdGoGetTransactionDataFromBlock(b.network.ToCfdValue(), block.Hex, txid)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get block tx error")
	}
	tx = &types.Transaction{Hex: txHex}
	txoutProof = types.NewByteDataFromHexIgnoreError(proof)
	return tx, txoutProof, nil
}

// ExistTxid ...
func (b *BlockApiImpl) ExistTxid(block *types.Block, txid string) (exist bool, err error) {
	if err = b.validConfig(); err != nil {
		return false, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	exist, err = cfd.CfdGoExistTxidInBlock(b.network.ToCfdValue(), block.Hex, txid)
	return exist, errors.Wrap(err, "check block txid error")
}

// validConfig ...
func (b *BlockApiImpl) validConfig() error {
	if b.network == nil {
		return cfdErrors.NetworkConfigError
	} else if !b.network.IsBitcoin() {
		return cfdErrors.BitcoinNetworkError
	}
	return nil
}
