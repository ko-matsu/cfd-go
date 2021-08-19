package types

type SignParameter struct {
	Data          Script
	IsDerEncode   bool
	SigHashType   SigHashType
	RelatedPubkey *Pubkey
}
