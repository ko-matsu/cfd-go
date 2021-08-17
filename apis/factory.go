package apis

import (
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/block"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

type CfdApiFactory interface {
	GetPubkeyApi() key.PubkeyApi
	GetPrivkeyApi() key.PrivkeyApi
	GetExtPubkeyApi() key.ExtPubkeyApi
	GetExtPrivkeyApi() key.ExtPrivkeyApi
	GetHdWalletApi() key.HdWalletApi

	GetBitcoinAddressApi() address.AddressApi
	GetBitcoinTxApi() transaction.TransactionApi
	GetBitcoinBlockApi() block.BlockApi
	GetBitcoinDescriptorApi() descriptor.DescriptorApi

	GetElementsAddressApi() address.ElementsAddressApi
	GetConfidentialAddressApi() address.ConfidentialAddressApi
	GetElementsTxApi() transaction.ConfidentialTxApi
	GetElementsDescriptorApi() descriptor.DescriptorApi
	GetLedgerLiquidLibApi() transaction.LedgerLiquidLibApi
}

// NewApiFactory returns an object that defines the API for all api factory.
func NewApiFactory(options ...config.CfdConfigOption) *ApiFactoryImpl {
	factory := ApiFactoryImpl{}
	var err error
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		factory.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network = conf.Network
	}

	var bitcoinAssetId *types.ByteData
	var bitcoinGenesisBlockHash *types.ByteData
	if network.IsElements() {
		if len(conf.BitcoinAssetId) != 0 {
			if bitcoinAssetId, err = utils.ValidAssetId(conf.BitcoinAssetId); err != nil {
				factory.SetError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
			}
		}
		if len(conf.BitcoinGenesisBlockHash) != 0 {
			if bitcoinGenesisBlockHash, err = utils.ValidBlockHash(conf.BitcoinGenesisBlockHash); err != nil {
				factory.SetError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
			}
		}
	}

	if network.Valid() {
		factory.network = &network
		if network.IsElements() {
			factory.bitcoinAssetId = bitcoinAssetId
			factory.bitcoinGenesisBlockHash = bitcoinGenesisBlockHash
		}
		btcNetworkOpt := config.NetworkOption(network.ToBitcoinType())

		factory.pubkeyApi = key.NewPubkeyApi()
		privkeyApi := key.NewPrivkeyApi(btcNetworkOpt)
		if privkeyApi.GetError() != nil {
			factory.SetError(privkeyApi.GetError())
		} else {
			factory.privkeyApi = privkeyApi
		}
		extPubkeyApi := key.NewExtPubkeyApi(btcNetworkOpt)
		if extPubkeyApi.GetError() != nil {
			factory.SetError(extPubkeyApi.GetError())
		} else {
			factory.extPubkeyApi = extPubkeyApi
		}
		extPrivkeyApi := key.NewExtPrivkeyApi(btcNetworkOpt)
		if extPrivkeyApi.GetError() != nil {
			factory.SetError(extPrivkeyApi.GetError())
		} else {
			factory.extPrivkeyApi = extPrivkeyApi
		}
		hdWalletApi := key.NewHdWalletApi(btcNetworkOpt)
		if hdWalletApi.GetError() != nil {
			factory.SetError(hdWalletApi.GetError())
		} else {
			factory.hdWalletApi = hdWalletApi
		}

		addressApi := address.NewAddressApi(btcNetworkOpt)
		if addressApi.GetError() != nil {
			factory.SetError(addressApi.GetError())
		} else {
			factory.bitcoinAddressApi = addressApi
		}
		blockApi := block.NewBlockApi(btcNetworkOpt)
		if blockApi.GetError() != nil {
			factory.SetError(blockApi.GetError())
		} else {
			factory.bitcoinBlockApi = blockApi
		}
		descriptorApi := descriptor.NewDescriptorApi(btcNetworkOpt).WithAddressApi(addressApi)
		if descriptorApi.GetError() != nil {
			factory.SetError(descriptorApi.GetError())
		} else {
			factory.bitcoinDescriptorApi = descriptorApi
		}
		bitcoinTxApi := transaction.NewTransactionApi(btcNetworkOpt).WithBitcoinDescriptorApi(descriptorApi)
		if bitcoinTxApi.GetError() != nil {
			factory.SetError(bitcoinTxApi.GetError())
		} else {
			factory.bitcoinTxApi = bitcoinTxApi
		}

		if network.IsElements() {
			elementsConfOpts := factory.getConfig().GetOptions()
			elementsAddrApi := address.NewAddressApi(elementsConfOpts...)
			if elementsAddrApi.GetError() != nil {
				factory.SetError(elementsAddrApi.GetError())
			} else {
				factory.elementsAddressApi = elementsAddrApi
			}
			elementsDescriptorApi := descriptor.NewDescriptorApi(elementsConfOpts...).WithAddressApi(elementsAddrApi)
			if elementsDescriptorApi.GetError() != nil {
				factory.SetError(elementsDescriptorApi.GetError())
			} else {
				factory.elementsDescriptorApi = elementsDescriptorApi
			}
			factory.confidentialAddressApi = address.NewConfidentialAddressApi()
			elementsTxApi := transaction.NewConfidentialTxApi(elementsConfOpts...).
				WithElementsDescriptorApi(elementsDescriptorApi).
				WithBitcoinAddressApi(addressApi).
				WithBitcoinTxApi(bitcoinTxApi)
			if elementsTxApi.GetError() != nil {
				factory.SetError(elementsTxApi.GetError())
			} else {
				factory.elementsTxApi = elementsTxApi
			}
			ledgerLibApi := transaction.NewLedgerLiquidLibApi(elementsConfOpts...).
				WithPrivkeyApi(privkeyApi)
			if ledgerLibApi.GetError() != nil {
				factory.SetError(ledgerLibApi.GetError())
			} else {
				factory.ledgerLiquidLibApi = ledgerLibApi
			}
		}
	}
	return &factory
}

type ApiFactoryImpl struct {
	cfdErrors.HasInitializeError
	network                 *types.NetworkType
	bitcoinGenesisBlockHash *types.ByteData
	bitcoinAssetId          *types.ByteData

	pubkeyApi     key.PubkeyApi
	privkeyApi    key.PrivkeyApi
	extPubkeyApi  key.ExtPubkeyApi
	extPrivkeyApi key.ExtPrivkeyApi
	hdWalletApi   key.HdWalletApi

	bitcoinAddressApi    address.AddressApi
	bitcoinDescriptorApi descriptor.DescriptorApi
	bitcoinBlockApi      block.BlockApi
	bitcoinTxApi         transaction.TransactionApi

	elementsAddressApi     address.ElementsAddressApi
	confidentialAddressApi address.ConfidentialAddressApi
	elementsDescriptorApi  descriptor.DescriptorApi
	elementsTxApi          transaction.ConfidentialTxApi
	ledgerLiquidLibApi     transaction.LedgerLiquidLibApi
}

func (p *ApiFactoryImpl) getConfig() *config.CfdConfig {
	conf := config.CfdConfig{Network: *p.network}
	if p.bitcoinAssetId != nil {
		conf.BitcoinAssetId = p.bitcoinAssetId.ToHex()
	}
	if p.bitcoinGenesisBlockHash != nil {
		conf.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	return &conf
}

func (a ApiFactoryImpl) GetPubkeyApi() key.PubkeyApi {
	return a.pubkeyApi
}
func (a ApiFactoryImpl) GetPrivkeyApi() key.PrivkeyApi {
	return a.privkeyApi
}
func (a ApiFactoryImpl) GetExtPubkeyApi() key.ExtPubkeyApi {
	return a.extPubkeyApi
}
func (a ApiFactoryImpl) GetExtPrivkeyApi() key.ExtPrivkeyApi {
	return a.extPrivkeyApi
}
func (a ApiFactoryImpl) GetHdWalletApi() key.HdWalletApi {
	return a.hdWalletApi
}

func (a ApiFactoryImpl) GetBitcoinAddressApi() address.AddressApi {
	return a.bitcoinAddressApi
}
func (a ApiFactoryImpl) GetBitcoinTxApi() transaction.TransactionApi {
	return a.bitcoinTxApi
}
func (a ApiFactoryImpl) GetBitcoinBlockApi() block.BlockApi {
	return a.bitcoinBlockApi
}
func (a ApiFactoryImpl) GetBitcoinDescriptorApi() descriptor.DescriptorApi {
	return a.bitcoinDescriptorApi
}

func (a ApiFactoryImpl) GetElementsAddressApi() address.ElementsAddressApi {
	return a.elementsAddressApi
}
func (a ApiFactoryImpl) GetConfidentialAddressApi() address.ConfidentialAddressApi {
	return a.confidentialAddressApi
}
func (a ApiFactoryImpl) GetElementsTxApi() transaction.ConfidentialTxApi {
	return a.elementsTxApi
}
func (a ApiFactoryImpl) GetElementsDescriptorApi() descriptor.DescriptorApi {
	return a.elementsDescriptorApi
}
func (a ApiFactoryImpl) GetLedgerLiquidLibApi() transaction.LedgerLiquidLibApi {
	return a.ledgerLiquidLibApi
}
