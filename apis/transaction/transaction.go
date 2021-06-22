package transaction

import (
	"fmt"
	"unsafe"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/types"
)

// -------------------------------------
// API
// -------------------------------------

type TransactionApi interface {
	// WithConfig This function set a configuration.
	WithConfig(conf config.CfdConfig) (obj *TransactionApiImpl, err error)
	Create(version uint32, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) (tx *types.Transaction, err error)
	Add(tx *types.Transaction, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error
	AddPubkeySign(tx *types.Transaction, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error
	AddPubkeySignByDescriptor(tx *types.Transaction, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error
	SignWithPrivkey(tx *types.Transaction, outpoint *types.OutPoint, privkey *types.Privkey, sighashType types.SigHashType, utxoList *[]types.UtxoData) error
	VerifySign(tx *types.Transaction, outpoint *types.OutPoint, amount int64, txinUtxoList *[]types.UtxoData) (isVerify bool, reason string, err error)
	GetTxid(tx *types.Transaction) string
	GetTxOut(tx *types.Transaction, vout uint32) (txout *types.TxOut, err error)
}

func NewTransactionApi() *TransactionApiImpl {
	cfdConfig := config.GetCurrentCfdConfig()
	api := TransactionApiImpl{}
	if cfdConfig.Network.Valid() {
		network := cfdConfig.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

// -------------------------------------
// TransactionApiImpl
// -------------------------------------

type TransactionApiImpl struct {
	network *types.NetworkType
}

// WithConfig This function set a configuration.
func (p *TransactionApiImpl) WithConfig(conf config.CfdConfig) (obj *TransactionApiImpl, err error) {
	if !conf.Network.Valid() {
		return p, fmt.Errorf("CFD Error: Invalid network configuration")
	}
	network := conf.Network.ToBitcoinType()
	p.network = &network
	return p, nil
}

func (t *TransactionApiImpl) Create(version uint32, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) (tx *types.Transaction, err error) {
	if err = t.validConfig(); err != nil {
		return nil, err
	}
	txHandle, err := cfd.InitializeTransaction(t.network.ToCfdValue(), version, locktime)
	if err != nil {
		return nil, err
	}
	defer cfd.FreeTransactionHandle(txHandle)

	if err = addTransaction(txHandle, locktime, txinList, txoutList); err != nil {
		return nil, err
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return nil, err
	}
	return &types.Transaction{Hex: txHex}, nil
}

func (t *TransactionApiImpl) Add(tx *types.Transaction, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	txHandle, err := cfd.InitializeTransactionByHex(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return err
	}
	defer cfd.FreeTransactionHandle(txHandle)

	data, err := cfd.CfdGoGetConfidentialTxDataByHandle(txHandle)
	if err != nil {
		return err
	}

	if err = addTransaction(txHandle, data.LockTime, txinList, txoutList); err != nil {
		return err
	}

	txHex, err := cfd.FinalizeTransaction(txHandle)
	if err != nil {
		return err
	}
	tx.Hex = txHex
	return nil
}

// AddPubkeySign ...
func (t *TransactionApiImpl) AddPubkeySign(tx *types.Transaction, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	signParam := cfd.CfdSignParameter{
		Data:                signature,
		IsDerEncode:         false,
		SighashType:         int(cfd.KCfdSigHashAll),
		SighashAnyoneCanPay: false,
	}
	txHex, err := cfd.CfdGoAddTxPubkeyHashSign(t.network.ToCfdValue(), tx.Hex, outpoint.Txid, outpoint.Vout, hashType.ToCfdValue(), pubkey.Hex, signParam)
	if err == nil {
		tx.Hex = txHex
	}
	return err
}

// AddPubkeySignByDescriptor ...
func (t *TransactionApiImpl) AddPubkeySignByDescriptor(tx *types.Transaction, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error {
	var err error
	if err = t.validConfig(); err != nil {
		return err
	}
	descUtil, err := descriptor.NewDescriptorApi().WithConfig(config.CfdConfig{Network: *t.network})
	if err != nil {
		return err
	}
	data, _, _, err := descUtil.Parse(outputDescriptor)
	if err != nil {
		return err
	}
	if data.HashType != int(cfd.KCfdP2pkh) && data.HashType != int(cfd.KCfdP2wpkh) && data.HashType != int(cfd.KCfdP2shP2wpkh) {
		return fmt.Errorf("CFD Error: Descriptor hashType is not pubkeyHash")
	}

	hashType := types.NewHashType(data.HashType)
	var pubkey types.Pubkey
	if data.KeyType == int(cfd.KCfdDescriptorKeyPublic) {
		pubkey.Hex = data.Pubkey
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPubkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return err
		}
	} else if data.KeyType == int(cfd.KCfdDescriptorKeyBip32Priv) {
		pubkey.Hex, err = cfd.CfdGoGetPubkeyFromExtkey(data.ExtPrivkey, t.network.ToBitcoinType().ToCfdValue())
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("CFD Error: Descriptor keyType is not pubkeyHash")
	}
	return t.AddPubkeySign(tx, outpoint, hashType, &pubkey, signature)
}

// SignWithPrivkey ...
func (t *TransactionApiImpl) SignWithPrivkey(tx *types.Transaction, outpoint *types.OutPoint, privkey *types.Privkey, sighashType types.SigHashType, utxoList *[]types.UtxoData) error {
	if err := t.validConfig(); err != nil {
		return err
	}
	cfdSighashType := cfd.SigHashType{
		Type:         sighashType.Type,
		AnyoneCanPay: sighashType.AnyoneCanPay,
		Rangeproof:   sighashType.Rangeproof,
	}
	txinUtxoList := (*[]cfd.CfdUtxo)(unsafe.Pointer(utxoList))
	txHex, err := cfd.CfdGoAddTxSignWithPrivkeyByUtxoList(t.network.ToCfdValue(), tx.Hex, *txinUtxoList, outpoint.Txid, outpoint.Vout, privkey.Hex, &cfdSighashType, true, nil, nil)
	if err == nil {
		tx.Hex = txHex
	}
	return err
}

// VerifySign ...
func (t *TransactionApiImpl) VerifySign(tx *types.Transaction, outpoint *types.OutPoint, amount int64, txinUtxoList *[]types.UtxoData) (isVerify bool, reason string, err error) {
	if err := t.validConfig(); err != nil {
		return false, "", err
	}
	utxoList := (*[]cfd.CfdUtxo)(unsafe.Pointer(txinUtxoList))
	return cfd.CfdGoVerifySign(t.network.ToCfdValue(), tx.Hex, *utxoList, outpoint.Txid, outpoint.Vout)
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
		return nil, err
	}
	handle, err := cfd.CfdGoInitializeTxDataHandle(t.network.ToCfdValue(), tx.Hex)
	if err != nil {
		return
	}
	defer cfd.CfdGoFreeTxDataHandle(handle)

	var output types.TxOut
	satoshiAmount, lockingScript, _, err := cfd.CfdGoGetTxOutByHandle(handle, vout)
	if err != nil {
		return nil, err
	}
	output.Amount = satoshiAmount
	output.LockingScript = lockingScript
	addr, tempErr := cfd.CfdGoGetAddressFromLockingScript(lockingScript, t.network.ToCfdValue())
	if tempErr == nil {
		output.Address = addr
	}
	return &output, nil
}

func (t *TransactionApiImpl) validConfig() error {
	if t.network == nil {
		return fmt.Errorf("CFD Error: NetworkType not set")
	} else if !t.network.IsBitcoin() {
		return fmt.Errorf("CFD Error: NetworkType is not bitcoin")
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
				return err
			}
		}
	}

	if txoutList != nil {
		for i := 0; i < len(*txoutList); i++ {
			err = cfd.AddTransactionOutput(txHandle, (*txoutList)[i].Amount, (*txoutList)[i].Address, (*txoutList)[i].LockingScript, "")
			if err != nil {
				return err
			}
		}
	}
	return nil
}
