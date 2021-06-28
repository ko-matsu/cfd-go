package types

/**
 * Descriptor data struct.
 */
type DescriptorData struct {
	// depth (0 - )
	Depth uint32
	// script type. (CfdDescriptorScriptType)
	ScriptType int
	// locking script.
	LockingScript string
	// address string. (for ScriptType not KCfdDescriptorScriptRaw)
	Address string
	// hash type. (CfdHashType)
	HashType int
	// redeem script. (for ScriptType KCfdDescriptorScriptSh or KCfdDescriptorScriptWsh)
	RedeemScript string
	// key type. (see CfdDescriptorKeyData.KeyType)
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
	// has multisig
	IsMultisig bool
	// number of multisig require signatures
	ReqSigNum uint32
	// Taproot ScriptTree string
	TreeString string
}

/**
 * Descriptor key data struct.
 */
type DescriptorKeyData struct {
	// key type. (CfdDescriptorKeyType)
	// - KCfdDescriptorKeyNull
	// - KCfdDescriptorKeyPublic
	// - KCfdDescriptorKeyBip32
	// - KCfdDescriptorKeyBip32Priv
	// - KCfdDescriptorKeySchnorr
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
}

// Descriptor This struct use for the output descriptor.
type Descriptor struct {
	// Output Descriptor
	OutputDescriptor string
	// Network Type
	Network *NetworkType
}
