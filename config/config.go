package config

import (
	"fmt"

	types "github.com/cryptogarageinc/cfd-go/types"
)

// GlobalConfig This struct is cfd's global configuration.
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
		return fmt.Errorf("CFD Error: Invalid network type")
	}
	if len(config.BitcoinGenesisBlockHash) > 0 {
		if _, err := types.NewByteDataFromHex(config.BitcoinGenesisBlockHash); err != nil {
			return err
		} else if len(config.BitcoinGenesisBlockHash) != 64 {
			return fmt.Errorf("CFD Error: Invalid blockHash length")
		}
		cfdConfig.BitcoinGenesisBlockHash = config.BitcoinGenesisBlockHash
	}
	if len(config.BitcoinAssetId) > 0 {
		if _, err := types.NewByteDataFromHex(config.BitcoinAssetId); err != nil {
			return err
		} else if len(config.BitcoinAssetId) != 64 {
			return fmt.Errorf("CFD Error: Invalid assetId length")
		}
		cfdConfig.BitcoinAssetId = config.BitcoinAssetId
	}
	return nil
}
