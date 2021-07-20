package pegout

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

// GetFuncName
func GetFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, ".")
	return funcName[index+1:]
}

func TestCreatePegoutTxByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:           20000000000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList)) // pegout, fee, output(change)
	assert.Less(t, 6780, len(tx.Hex))
	assert.Greater(t, 6800, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(179), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, &utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, &signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, &utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, &signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxWithUnblindUtxoByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	txouts := []types.InputConfidentialTxOut{
		{
			Amount:  200000000000000,
			Address: "lq1qqgv5wwfp4h0pfnyy2kkxl0kg3qnahcpfq7emrxu9xusz879axq0spg9cxu8wf72ktsft5r8vxnkfd8s5kmg32fvy8texp5p6s",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, &txouts, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, output(send), change
	assert.Less(t, 17310, len(tx.Hex))
	assert.Greater(t, 17320, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(200000000000000), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, &utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, &signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, &utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, &signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxWithAppendDummyByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	opts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := key.NewExtPrivkeyApi(opts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(opts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(opts...)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutApi := NewPegoutService(opts...)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, &utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, &signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, &utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, &signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutOverrideApis(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	confOpts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	btcNetworkConf := config.NetworkOption(types.Mainnet)
	btcAddrApi := address.NewAddressApi(btcNetworkConf)
	assert.NoError(t, btcAddrApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcAddrApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	btcDescApi := descriptor.NewDescriptorApi(btcNetworkConf)
	assert.NoError(t, btcDescApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcDescApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	elmDescApi := descriptor.NewDescriptorApi(confOpts...)
	assert.NoError(t, elmDescApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(elmDescApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	btcTxApi := transaction.NewTransactionApi(btcNetworkConf).WithBitcoinDescriptorApi(btcDescApi)
	assert.NoError(t, btcTxApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcTxApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pubkeyApi := key.NewPubkeyApi()
	xprvApi := key.NewExtPrivkeyApi(confOpts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(confOpts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(confOpts...).
		WithElementsDescriptorApi(elmDescApi).
		WithBitcoinAddressApi(btcAddrApi).WithBitcoinTxApi(btcTxApi)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutApi := NewPegoutService(confOpts...).
		WithBitcoinAddressApi(btcAddrApi).
		WithElementsDescriptorApi(elmDescApi).
		WithConfidentialTxApi(txApi).WithPubkeyApi(pubkeyApi)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, &utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, &signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, &utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, &signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

const DescriptorParseMockErrorMessage = "Mock Descriptor.Parse called"

type DescriptorApiParserMock struct {
	descriptor.DescriptorApi
}

func NewDescriptorApiParserMock(network types.NetworkType) *DescriptorApiParserMock {
	descObj := descriptor.NewDescriptorApi(config.NetworkOption(network))
	obj := DescriptorApiParserMock{descObj}
	return &obj
}

func (d *DescriptorApiParserMock) Parse(descriptor *types.Descriptor) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData, err error) {
	return nil, nil, nil, errors.New(DescriptorParseMockErrorMessage)
}

func TestPegoutServiceOverrideApiByMock(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	confOpts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	myDescObj := NewDescriptorApiParserMock(curConfig.Network)
	xprvApi := key.NewExtPrivkeyApi(confOpts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(confOpts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(confOpts...)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutApi := NewPegoutService(confOpts...).WithElementsDescriptorApi(myDescObj)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, &utxos)
	assert.NoError(t, err)
	// utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, &signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, &utxos[0], signature)
	assert.Error(t, err)
	// assert.NoError(t, err)
	assert.Contains(t, err.Error(), DescriptorParseMockErrorMessage)
	assert.False(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}
