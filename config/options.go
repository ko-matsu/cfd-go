package config

import (
	types "github.com/cryptogarageinc/cfd-go/types"
)

type CfdConfigOption func(*CfdConfig)

// NetworkOpt returns configuration option function.
func NetworkOpt(networkType types.NetworkType) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.Network = networkType
		}
	}
}

// BitcoinGenesisBlockHashOpt returns configuration option function.
func BitcoinGenesisBlockHashOpt(genesisBlockHash string) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.BitcoinGenesisBlockHash = genesisBlockHash
		}
	}
}

// BitcoinAssetIdOpt returns configuration option function.
func BitcoinAssetIdOpt(bitcoinAssetId string) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.BitcoinAssetId = bitcoinAssetId
		}
	}
}
