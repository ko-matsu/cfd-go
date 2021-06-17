package types

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

type ElementsUtxoData struct {
	OutPoint          OutPoint // OutPoint
	Asset             string   // Asset
	AssetBlindFactor  string   // Asset BlindFactor
	Amount            int64    // satoshi value
	ValueBlindFactor  string   // Value BlindFactor
	Descriptor        string   // output descriptor
	ScriptSigTemplate string   // scriptsig template hex (require script hash estimate fee)
	IssuanceKey       *IssuanceBlindingKey
	IsIssuance        bool // is issuance output
	IsBlindIssuance   bool // is blind issuance output
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
