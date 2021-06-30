package key

import (
	"testing"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestCfdPrivkeyAndPubkey(t *testing.T) {
	// pubkeyApi := (PubkeyApi)(NewPubkeyApi())

	var privkeyApi PrivkeyApi
	network := types.Regtest
	privkeyApi, err := NewPrivkeyApi().WithConfig(config.CfdConfig{Network: network})
	assert.NoError(t, err)

	// compress
	pubkeyHex, privkeyHex, wif, err := cfd.CfdGoCreateKeyPair(true, network.ToCfdValue())
	assert.NoError(t, err)
	assert.Equal(t, 66, len(pubkeyHex))
	assert.Equal(t, 64, len(privkeyHex))
	assert.Equal(t, 52, len(wif))
	pubkey := &types.Pubkey{Hex: pubkeyHex}

	privkey, err := privkeyApi.GetPrivkeyFromWif(wif)
	assert.NoError(t, err)
	assert.Equal(t, privkeyHex, privkey.Hex)
	assert.Equal(t, wif, privkey.Wif)
	assert.Equal(t, types.Testnet, privkey.Network)
	assert.Equal(t, true, privkey.IsCompressedPubkey)

	// wif2, err := CfdGoGetPrivkeyWif(privkey, kNetwork, true)
	// assert.NoError(t, err)
	// assert.Equal(t, wif, wif2)

	pubkey2, err := privkeyApi.GetPubkey(privkey)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.Hex, pubkey2.Hex)
}
