package config

import (
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

// ConfigType This type is cfd's configuration type.
type CfdConfigType int

const (
	NetworkConfig CfdConfigType = iota
	BitcoinGenesisBlockHashConfig
	BitcoinAssetIdConfig
)

// CfdConfig This struct is cfd's configuration.
type CfdConfig struct {
	Network                 types.NetworkType
	BitcoinGenesisBlockHash string
	BitcoinAssetId          string
}

var cfdConfig CfdConfig

// GetCurrentCfdConfig ...
func GetCurrentCfdConfig() CfdConfig {
	return CfdConfig{
		Network:                 cfdConfig.Network,
		BitcoinGenesisBlockHash: cfdConfig.BitcoinGenesisBlockHash,
		BitcoinAssetId:          cfdConfig.BitcoinAssetId,
	}
}

// SetCfdConfig ...
func SetCfdConfig(config CfdConfig) error {
	if config.Network.Valid() {
		cfdConfig.Network = config.Network
	} else {
		return errors.Errorf("CFD Error: Invalid network type(%d)", config.Network)
	}
	if len(config.BitcoinGenesisBlockHash) > 0 {
		if _, err := utils.ValidBlockHash(config.BitcoinGenesisBlockHash); err != nil {
			return errors.Wrap(err, "validate blockhash error")
		}
		cfdConfig.BitcoinGenesisBlockHash = config.BitcoinGenesisBlockHash
	}
	if len(config.BitcoinAssetId) > 0 {
		if _, err := utils.ValidAssetId(config.BitcoinAssetId); err != nil {
			return errors.Wrap(err, "validate assetId error")
		}
		cfdConfig.BitcoinAssetId = config.BitcoinAssetId
	}
	return nil
}

// GetConfigOptions ...
func (config CfdConfig) GetOptions() []CfdConfigOption {
	result := make([]CfdConfigOption, 0, 3)
	if config.Network.Valid() {
		result = append(result, NetworkOpt(config.Network))
	}
	if _, err := utils.ValidBlockHash(config.BitcoinGenesisBlockHash); err == nil {
		result = append(result, BitcoinGenesisBlockHashOpt(config.BitcoinGenesisBlockHash))
	}
	if _, err := utils.ValidAssetId(config.BitcoinAssetId); err == nil {
		result = append(result, BitcoinAssetIdOpt(config.BitcoinAssetId))
	}
	return result
}

// GetGlobalConfigOptions ...
func GetGlobalConfigOptions() []CfdConfigOption {
	result := cfdConfig.GetOptions()
	return result
}
