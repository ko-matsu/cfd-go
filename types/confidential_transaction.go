package types

import (
	cfd "github.com/cryptogarageinc/cfd-go"
)

const (
	CommitmentDataSize    = 33
	CommitmentHexDataSize = 66
	EmptyBlinder          = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ConfidentialTx ...
type ConfidentialTx struct {
	Hex string
}

// IssuanceData confidential transaction issuance input.
type IssuanceData struct {
	Entropy     string
	Nonce       string
	AssetAmount int64
	AssetValue  string
	TokenAmount int64
	TokenValue  string
}

// ConfidentialTxIn confidential transaction input.
type ConfidentialTxIn struct {
	OutPoint                 OutPoint
	Sequence                 uint32
	ScriptSig                string
	Issuance                 IssuanceData
	WitnessStack             ScriptWitness
	PeginWitness             ScriptWitness
	IssuanceAmountRangeproof string
	InflationKeysRangeproof  string
}

// ConfidentialTxOut confidential transaction output.
type ConfidentialTxOut struct {
	Amount          int64  // satoshi amount (unblind value)
	Asset           string // asset (or commitment asset)
	LockingScript   string // locking script
	Address         string // address or confidential address. (if locking script is usual hashtype.)
	CommitmentValue string // commitment value
	CommitmentNonce string // commitment nonce
	Surjectionproof string // surjectionprooof of asset
	Rangeproof      string // rangeproof of value
}

// InputConfidentialTxIn ...
type InputConfidentialTxIn struct {
	OutPoint   OutPoint
	Sequence   uint32
	PeginInput *InputPeginData
}

// InputConfidentialTxOut ...
type InputConfidentialTxOut struct {
	Amount        int64  // satoshi amount (unblind value)
	Asset         string // asset (or commitment asset)
	LockingScript string // locking script
	Address       string // address or confidential address. (if locking script is usual hashtype.)
	Nonce         string // direct nonce
	PegoutInput   *InputPegoutData
	IsDestroy     bool
	IsFee         bool
}

// InputPeginData ...
type InputPeginData struct {
	BitcoinTransaction      string
	BitcoinGenesisBlockHash string
	BitcoinAssetId          string
	ClaimScript             string
	TxOutProof              string
}

// InputPegoutData ...
type InputPegoutData struct {
	BitcoinGenesisBlockHash string
	OnlineKey               string
	BitcoinOutputDescriptor string
	Bip32Counter            uint32
	Whitelist               string
}

// IssuanceBlindingKey ...
type IssuanceBlindingKey struct {
	AssetBlindingKey string // (option) Asset blinding key
	TokenBlindingKey string // (option) Token blinding key
}

/**
 * FundRawTransaction option data struct.
 */
type FundRawTxOption struct {
	// fee asset
	FeeAsset string
	// use blind tx
	IsBlindTx bool
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value. knapsack logic's threshold. Recommended value is 1.
	KnapsackMinChange int64
	// blind exponent. default is 0.
	Exponent int64
	// blind minimum bits. default is -1 (cfd-go auto).
	MinimumBits int64
}

type PeginUtxoData struct {
	BitcoinTransaction string
	TxOutProof         string
	ClaimScript        string
}

type ElementsUtxoData struct {
	OutPoint          OutPoint             // OutPoint
	Asset             string               // Asset
	AssetBlindFactor  string               // Asset BlindFactor
	Amount            int64                // satoshi value
	ValueBlindFactor  string               // Value BlindFactor
	AmountCommitment  string               // Amount commitment
	Descriptor        string               // output descriptor
	ScriptSigTemplate string               // scriptsig template hex (require script hash estimate fee)
	IssuanceKey       *IssuanceBlindingKey // issuance key
	IsIssuance        bool                 // is issuance output
	IsBlindIssuance   bool                 // is blind issuance output
	PeginData         *PeginUtxoData       // pegin data
}

// BlindInputData ...
type BlindInputData struct {
	OutPoint         OutPoint // OutPoint
	Asset            string   // Asset
	AssetBlindFactor string   // Asset BlindFactor
	Amount           int64    // satoshi value
	ValueBlindFactor string   // Value BlindFactor
	IssuanceKey      *IssuanceBlindingKey
}

// BlindOutputData ...
type BlindOutputData struct {
	Index               int    // txout index (-1: auto)
	ConfidentialAddress string // confidential or not address
	ConfidentialKey     string // (optional) confidential key
}

// BlindTxOption BlindRawTransaction option data struct.
type BlindTxOption struct {
	MinimumRangeValue int64 // blind minimum range value
	Exponent          int64 // blind exponent
	MinimumBits       int64 // blind minimum bits
	AppendDummyOutput bool  // add dummy output if txout is low
}

// NewBlindTxOption ...
func NewBlindTxOption() BlindTxOption {
	option := BlindTxOption{}
	option.MinimumRangeValue = int64(1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	option.AppendDummyOutput = false
	return option
}

func NewCfdFundRawTxOption(networkType NetworkType) FundRawTxOption {
	option := FundRawTxOption{}
	if networkType.IsElements() {
		option.FeeAsset = "0000000000000000000000000000000000000000000000000000000000000000"
		option.IsBlindTx = true
		option.EffectiveFeeRate = float64(0.15)
		option.LongTermFeeRate = float64(-1.0)
		option.DustFeeRate = float64(-1.0)
		option.KnapsackMinChange = int64(-1)
		option.Exponent = int64(0)
		option.MinimumBits = int64(-1)
	} else {
		option.EffectiveFeeRate = float64(20.0)
		option.LongTermFeeRate = float64(-1.0)
		option.DustFeeRate = float64(-1.0)
		option.KnapsackMinChange = int64(-1)
	}
	return option
}

// FIXME move to pegin.go types

// PeginTxOption ...
type PeginTxOption struct {
	// fee asset
	FeeAsset string
	// use blind tx
	IsBlindTx bool
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value. knapsack logic's threshold. Recommended value is 1.
	KnapsackMinChange int64
	// blind minimum range value
	MinimumRangeValue int64
	// blind exponent. default is 0.
	Exponent int64
	// blind minimum bits. default is -1 (cfd-go auto).
	MinimumBits int64
}

// NewPeginTxOption ...
func NewPeginTxOption() PeginTxOption {
	option := PeginTxOption{}
	option.FeeAsset = "0000000000000000000000000000000000000000000000000000000000000000"
	option.IsBlindTx = true
	option.EffectiveFeeRate = float64(0.15)
	option.LongTermFeeRate = float64(-1.0)
	option.DustFeeRate = float64(-1.0)
	option.KnapsackMinChange = int64(-1)
	option.MinimumRangeValue = int64(1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	return option
}

// PegoutTxOption ...
type PegoutTxOption struct {
	// fee asset
	FeeAsset string
	// use blind tx
	IsBlindTx bool
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value. knapsack logic's threshold. Recommended value is 1.
	KnapsackMinChange int64
	// blind minimum range value
	MinimumRangeValue int64
	// blind exponent. default is 0.
	Exponent int64
	// blind minimum bits. default is -1 (cfd-go auto).
	MinimumBits int64
}

// NewPegoutTxOption ...
func NewPegoutTxOption() PegoutTxOption {
	option := PegoutTxOption{}
	option.FeeAsset = "0000000000000000000000000000000000000000000000000000000000000000"
	option.IsBlindTx = true
	option.EffectiveFeeRate = float64(0.15)
	option.LongTermFeeRate = float64(-1.0)
	option.DustFeeRate = float64(-1.0)
	option.KnapsackMinChange = int64(-1)
	option.MinimumRangeValue = int64(1)
	option.Exponent = int64(0)
	option.MinimumBits = int64(-1)
	return option
}

func (u ElementsUtxoData) HasBlindUtxo() bool {
	if (len(u.AssetBlindFactor) == 64) && (len(u.ValueBlindFactor) == 64) &&
		(u.AssetBlindFactor != EmptyBlinder) && (u.ValueBlindFactor != EmptyBlinder) {
		return true
	}
	return false
}

func (u ElementsUtxoData) ConvertToCfdUtxo() cfd.CfdUtxo {
	utxo := cfd.CfdUtxo{
		Txid:              u.OutPoint.Txid,
		Vout:              u.OutPoint.Vout,
		Amount:            u.Amount,
		Asset:             u.Asset,
		Descriptor:        u.Descriptor,
		AmountCommitment:  u.AmountCommitment,
		IsIssuance:        u.IsIssuance,
		IsBlindIssuance:   u.IsBlindIssuance,
		ScriptSigTemplate: u.ScriptSigTemplate,
	}
	if (u.IssuanceKey != nil) && (len(u.IssuanceKey.AssetBlindingKey) == 64) {
		utxo.IsIssuance = true
		utxo.IsBlindIssuance = true
	}
	if u.PeginData != nil {
		utxo.IsPegin = true
		utxo.ClaimScript = u.PeginData.ClaimScript
		utxo.PeginBtcTxSize = uint32(len(u.PeginData.BitcoinTransaction) / 2)
		utxo.PeginTxOutProofSize = uint32(len(u.PeginData.TxOutProof) / 2)
	}
	return utxo
}

func NewConfidentialTxIn(cfdTxin *cfd.ConfidentialTxIn) *ConfidentialTxIn {
	data := ConfidentialTxIn{
		OutPoint: OutPoint{
			Txid: cfdTxin.OutPoint.Txid,
			Vout: cfdTxin.OutPoint.Vout,
		},
		Sequence:  cfdTxin.Sequence,
		ScriptSig: cfdTxin.ScriptSig,
	}
	if cfdTxin.Issuance.Entropy != "" {
		data.Issuance.Entropy = cfdTxin.Issuance.Entropy
		data.Issuance.Nonce = cfdTxin.Issuance.Nonce
		data.Issuance.AssetAmount = cfdTxin.Issuance.AssetAmount
		data.Issuance.AssetValue = cfdTxin.Issuance.AssetValue
		data.Issuance.TokenAmount = cfdTxin.Issuance.TokenAmount
		data.Issuance.TokenValue = cfdTxin.Issuance.TokenValue
		data.IssuanceAmountRangeproof = cfdTxin.IssuanceAmountRangeproof
		data.InflationKeysRangeproof = cfdTxin.InflationKeysRangeproof
	}
	if len(cfdTxin.WitnessStack.Stack) > 0 {
		data.WitnessStack.Stack = cfdTxin.WitnessStack.Stack
	}
	if len(cfdTxin.PeginWitness.Stack) > 0 {
		data.PeginWitness.Stack = cfdTxin.PeginWitness.Stack
	}
	return &data
}

func NewConfidentialTxOut(cfdTxout *cfd.ConfidentialTxOut) *ConfidentialTxOut {
	data := ConfidentialTxOut{
		LockingScript:   cfdTxout.LockingScript,
		Address:         cfdTxout.Address,
		Amount:          cfdTxout.Amount,
		CommitmentValue: cfdTxout.CommitmentValue,
		Asset:           cfdTxout.Asset,
		CommitmentNonce: cfdTxout.CommitmentNonce,
		Surjectionproof: cfdTxout.Surjectionproof,
		Rangeproof:      cfdTxout.Rangeproof,
	}
	return &data
}
