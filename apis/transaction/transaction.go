package transaction

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

// -------------------------------------
// API
// -------------------------------------

type TransactionApi interface {
	Create(version uint32, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) (tx *types.Transaction, err error)
	Add(tx *types.Transaction, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error
	AddPubkeySign(tx *types.Transaction, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error
	AddPubkeySignByDescriptor(tx *types.Transaction, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error
	SignWithPrivkey(tx *types.Transaction, outpoint *types.OutPoint, privkey *types.Privkey, sighashType types.SigHashType, utxoList *[]types.UtxoData) error
	VerifySign(tx *types.Transaction, outpoint *types.OutPoint, amount int64, txinUtxoList *[]types.UtxoData) (isVerify bool, reason string, err error)
	GetTxid(tx *types.Transaction) string
	GetTxOut(tx *types.Transaction, vout uint32) (txout *types.TxOut, err error)
}

func NewTransactionApi(overrideInterfaces ...interface{}) *TransactionApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := TransactionApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	api.WithInterfaces(overrideInterfaces...)
	return &api
}

// -------------------------------------
// TransactionApiImpl
// -------------------------------------

type TransactionApiImpl struct {
	network       *types.NetworkType
	descriptorApi descriptor.DescriptorApi
}

// WithConfig This function set a configuration.
func (p *TransactionApiImpl) WithConfig(conf config.CfdConfig, overrideInterfaces ...interface{}) (obj *TransactionApiImpl, err error) {
	obj = p
	if !conf.Network.Valid() {
		return obj, cfdErrors.NetworkConfigError
	} else if _, err = p.WithInterfaces(overrideInterfaces...); err != nil {
		return obj, errors.Wrap(err, cfdErrors.InterfaceSettingErrorMessage)
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return obj, nil
}

// WithInterfaces This function set a interface.
func (p *TransactionApiImpl) WithInterfaces(interfaces ...interface{}) (obj *TransactionApiImpl, err error) {
	obj = p
	if len(interfaces) == 0 {
		return obj, nil
	}
	descriptorApi := p.descriptorApi
	for _, apiInterface := range interfaces {
		if descApi, ok := apiInterface.(descriptor.DescriptorApi); ok && utils.ValidNetworkTypes(descApi.GetNetworkTypes(), types.Mainnet) {
			descriptorApi = descApi
		}
	}
	if descriptorApi == nil {
		return obj, cfdErrors.InterfaceSettingError
	}
	p.descriptorApi = descriptorApi
	return obj, nil
}

func (t *TransactionApiImpl) getDescriptorApi() (api descriptor.DescriptorApi, err error) {
	api = t.descriptorApi
	if t.descriptorApi == nil {
		if api, err = descriptor.NewDescriptorApi().WithConfig(config.CfdConfig{Network: *t.network}); err != nil {
			return nil, errors.Wrap(err, "create DescriptorApi error")
		}
	}
	return api, nil
}

func (t *TransactionApiImpl) Create(version uint32, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) (tx *types.Transaction, err error) {
	if err = t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	txHandle, err := cfd.InitializeTransaction(t.network.ToCfdValue(), version, locktime)
	if err != nil {
		return nil, errors.Wrap(err, "initialize tx error")
	}
	defer cfd.FreeTransactionHandle(txHandle)

	if err = addTransaction(txHandle, locktime, txinList, txoutList); err != nil {
		return nil, errors.Wrap(err, "add tx error")
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return nil, errors.Wrap(err, "finalize tx error")
	}
	tx = &types.Transaction{Hex: txHex}
	return tx, nil
}

func (t *TransactionApiImpl) Add(tx *types.Transaction, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error {
	if err := t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	txHandle, err := cfd.InitializeTransactionByHex(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return errors.Wrap(err, "initialize tx error")
	}
	defer cfd.FreeTransactionHandle(txHandle)

	data, err := cfd.CfdGoGetConfidentialTxDataByHandle(txHandle)
	if err != nil {
		return errors.Wrap(err, "get tx data error")
	}

	if err = addTransaction(txHandle, data.LockTime, txinList, txoutList); err != nil {
		return errors.Wrap(err, "add tx error")
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return errors.Wrap(err, "finalize tx error")
	}
	tx.Hex = txHex
	return nil
}

// AddPubkeySign ...
func (t *TransactionApiImpl) AddPubkeySign(tx *types.Transaction, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error {
	if err := t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	signParam := cfd.CfdSignParameter{
		Data:                signature,
		IsDerEncode:         false,
		SighashType:         int(cfd.KCfdSigHashAll),
		SighashAnyoneCanPay: false,
	}
	txHex, err := cfd.CfdGoAddTxPubkeyHashSign(t.network.ToCfdValue(), tx.Hex, outpoint.Txid, outpoint.Vout, hashType.ToCfdValue(), pubkey.Hex, signParam)
	if err != nil {
		return errors.Wrap(err, "add pubkey hash sign error")
	}
	tx.Hex = txHex
	return nil
}

// AddPubkeySignByDescriptor ...
func (t *TransactionApiImpl) AddPubkeySignByDescriptor(tx *types.Transaction, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error {
	var err error
	if err = t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	descUtil, err := t.getDescriptorApi()
	if err != nil {
		return errors.Wrap(err, cfdErrors.CreateDefaultApiErrorMessage)
	}
	data, _, _, err := descUtil.Parse(outputDescriptor)
	if err != nil {
		return errors.Wrap(err, "parse descriptor error")
	}
	if data.HashType != int(cfd.KCfdP2pkh) && data.HashType != int(cfd.KCfdP2wpkh) && data.HashType != int(cfd.KCfdP2shP2wpkh) {
		return errors.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
	}

	hashType := types.NewHashType(data.HashType)
	var pubkey types.Pubkey
	if data.KeyType == int(cfd.KCfdDescriptorKeyPublic) {
		pubkey.Hex = data.Pubkey
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return errors.Wrap(err, "get pubkey error")
		}
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32Priv) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return errors.Wrap(err, "get pubkey error")
		}
	} else {
		return errors.Errorf("CFD Error: Descriptor keyType is not pubkeyHash")
	}
	return t.AddPubkeySign(tx, outpoint, hashType, &pubkey, signature)
}

// SignWithPrivkey ...
func (t *TransactionApiImpl) SignWithPrivkey(tx *types.Transaction, outpoint *types.OutPoint, privkey *types.Privkey, sighashType types.SigHashType, utxoList *[]types.UtxoData) error {
	if err := t.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	cfdSighashType := cfd.SigHashType{
		Type:         sighashType.Type,
		AnyoneCanPay: sighashType.AnyoneCanPay,
		Rangeproof:   sighashType.Rangeproof,
	}
	txinUtxoList := []cfd.CfdUtxo{}
	if utxoList != nil {
		txinUtxoList = make([]cfd.CfdUtxo, len(*utxoList))
		for i, utxo := range *utxoList {
			txinUtxoList[i] = utxo.ConvertToCfdUtxo()
		}
	}
	txHex, err := cfd.CfdGoAddTxSignWithPrivkeyByUtxoList(t.network.ToCfdValue(), tx.Hex, txinUtxoList, outpoint.Txid, outpoint.Vout, privkey.Hex, &cfdSighashType, true, nil, nil)
	if err != nil {
		return errors.Wrap(err, "add sign error")
	}
	tx.Hex = txHex
	return nil
}

// VerifySign ...
func (t *TransactionApiImpl) VerifySign(tx *types.Transaction, outpoint *types.OutPoint, amount int64, txinUtxoList *[]types.UtxoData) (isVerify bool, reason string, err error) {
	if err := t.validConfig(); err != nil {
		return false, "", errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	utxoList := []cfd.CfdUtxo{}
	if txinUtxoList != nil {
		utxoList = make([]cfd.CfdUtxo, len(*txinUtxoList))
		for i, utxo := range *txinUtxoList {
			utxoList[i] = utxo.ConvertToCfdUtxo()
		}
	}
	return cfd.CfdGoVerifySign(t.network.ToCfdValue(), tx.Hex, utxoList, outpoint.Txid, outpoint.Vout)
}

func (t *TransactionApiImpl) GetTxid(tx *types.Transaction) string {
	if err := t.validConfig(); err != nil {
		return ""
	}
	handle, err := cfd.CfdGoInitializeTxDataHandle(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return ""
	}
	defer cfd.CfdGoFreeTxDataHandle(handle)

	data, err := cfd.CfdGoGetTxInfoByHandle(handle)
	if err != nil {
		return ""
	}
	return data.Txid
}

func (t *TransactionApiImpl) GetTxOut(tx *types.Transaction, vout uint32) (txout *types.TxOut, err error) {
	if err := t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	handle, err := cfd.CfdGoInitializeTxDataHandle(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return
	}
	defer cfd.CfdGoFreeTxDataHandle(handle)

	var output types.TxOut
	satoshiAmount, lockingScript, _, err := cfd.CfdGoGetTxOutByHandle(handle, vout)
	if err != nil {
		return nil, errors.Wrapf(err, "get txout error(%d)", vout)
	}
	output.Amount = satoshiAmount
	output.LockingScript = lockingScript
	// FIXME(k-matsuzawa): This function need wrapped by AddressApi.
	addr, tempErr := cfd.CfdGoGetAddressFromLockingScript(lockingScript, t.network.ToCfdValue())
	if tempErr == nil {
		output.Address = addr
	}
	txout = &output
	return txout, nil
}

func (t *TransactionApiImpl) validConfig() error {
	if t.network == nil {
		return cfdErrors.NetworkConfigError
	} else if !t.network.IsBitcoin() {
		return cfdErrors.BitcoinNetworkError
	}
	return nil
}

// addConidentialTx ...
func addTransaction(txHandle uintptr, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error {
	var err error
	if txinList != nil {
		for i := 0; i < len(*txinList); i++ {
			seq := (*txinList)[i].Sequence
			if seq == 0 {
				if locktime == 0 {
					seq = uint32(cfd.KCfdSequenceLockTimeFinal)
				} else {
					seq = uint32(cfd.KCfdSequenceLockTimeEnableMax)
				}
			}
			err = cfd.AddTransactionInput(txHandle, (*txinList)[i].OutPoint.Txid, (*txinList)[i].OutPoint.Vout, seq)
			if err != nil {
				return errors.Wrap(err, "add txin error")
			}
		}
	}

	if txoutList != nil {
		for i := 0; i < len(*txoutList); i++ {
			err = cfd.AddTransactionOutput(txHandle, (*txoutList)[i].Amount, (*txoutList)[i].Address, (*txoutList)[i].LockingScript, "")
			if err != nil {
				return errors.Wrap(err, "add txout error")
			}
		}
	}
	return nil
}
