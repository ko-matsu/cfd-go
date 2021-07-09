package utils

import (
	"fmt"

	"github.com/cryptogarageinc/cfd-go/types"
)

// ValidAssetId This function validate an assetId.
func ValidAssetId(assetId string) (assetIdBytes *types.ByteData, err error) {
	tempBytes, err := types.NewByteDataFromHex(assetId)
	if (err != nil) || (len(assetId) != 64) {
		return nil, fmt.Errorf("CFD Error: Invalid assetId configuration")
	}
	assetIdBytes = &tempBytes
	return assetIdBytes, nil
}

// ValidBlockHash This function validate a blockHash.
func ValidBlockHash(blockHash string) (blockHashBytes *types.ByteData, err error) {
	tempBytes, err := types.NewByteDataFromHex(blockHash)
	if (err != nil) || (len(blockHash) != 64) {
		return nil, fmt.Errorf("CFD Error: Invalid blockHash configuration")
	}
	blockHashBytes = &tempBytes
	return blockHashBytes, nil
}
