package config

import (
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	types "github.com/cryptogarageinc/cfd-go/types"
)

type CfdConfigOption func(*CfdConfig) CfdConfigType

// NetworkOpt returns configuration option function.
func NetworkOpt(networkType types.NetworkType) CfdConfigOption {
	return func(conf *CfdConfig) CfdConfigType {
		if conf != nil {
			conf.Network = networkType
		}
		return NetworkConfig
	}
}

// BitcoinGenesisBlockHashOpt returns configuration option function.
func BitcoinGenesisBlockHashOpt(genesisBlockHash string) CfdConfigOption {
	return func(conf *CfdConfig) CfdConfigType {
		if conf != nil {
			conf.BitcoinGenesisBlockHash = genesisBlockHash
		}
		return BitcoinGenesisBlockHashConfig
	}
}

// BitcoinAssetIdOpt returns configuration option function.
func BitcoinAssetIdOpt(bitcoinAssetId string) CfdConfigOption {
	return func(conf *CfdConfig) CfdConfigType {
		if conf != nil {
			conf.BitcoinAssetId = bitcoinAssetId
		}
		return BitcoinAssetIdConfig
	}
}

// ConvertOptionsWithCurrentCfdConfig ...
func ConvertOptionsWithCurrentCfdConfig(options ...CfdConfigOption) (conf CfdConfig, err error) {
	errs := cfdErrors.NewMultiError(
		cfdErrors.CfdError("Failed to ConvertOptionsWithCurrentCfdConfig"))
	opts := make(map[CfdConfigType]CfdConfigOption)
	if len(options) > 0 {
		for _, option := range options {
			if option != nil {
				optType := option(nil)
				_, ok := opts[optType]
				if ok {
					errs.Add(cfdErrors.DuplicateOptionError)
				} else {
					opts[optType] = option
				}
			}
		}
	}
	// set global option
	for _, option := range GetGlobalConfigOptions() {
		optType := option(nil)
		_, ok := opts[optType]
		if !ok {
			opts[optType] = option
		}
	}

	for _, optFunc := range opts {
		optFunc(&conf)
	}
	if errs.Exist() {
		err = errs
	}
	return conf, err
}
