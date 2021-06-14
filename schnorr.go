package cfdgo

// SchnorrUtil This struct use for the accessing to schnorr function.
type SchnorrUtil struct {
}

// NewSchnorrUtil This function return a SchnorrUtil.
func NewSchnorrUtil() *SchnorrUtil {
	return &SchnorrUtil{}
}

// GetPubkeyFromPrivkey (deprecated) This function return a schnorr's pubkey. Please use GetSchnorrPubkeyFromPrivkey.
func (obj *SchnorrUtil) GetPubkeyFromPrivkey(key ByteData) (pubkey ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	parity := false
	ret := CfdGetSchnorrPubkeyFromPrivkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, err
}

// GetSchnorrPubkeyFromPrivkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) GetSchnorrPubkeyFromPrivkey(key ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	ret := CfdGetSchnorrPubkeyFromPrivkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, parity, err
}

// GetSchnorrPubkeyFromPubkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) GetSchnorrPubkeyFromPubkey(key ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrPubkey string
	ret := CfdGetSchnorrPubkeyFromPubkey(handle, key.ToHex(), &schnorrPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: schnorrPubkey}
	}
	return pubkey, parity, err
}

// TweakAddKeyPair This function return a schnorr's pubkey.
func (obj *SchnorrUtil) TweakAddKeyPair(key, tweak ByteData) (pubkey ByteData, parity bool, privkey ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var tweakedPubkey string
	var tweakedPrivkey string
	ret := CfdSchnorrKeyPairTweakAdd(handle, key.ToHex(), tweak.ToHex(), &tweakedPubkey, &parity, &tweakedPrivkey)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: tweakedPubkey}
		privkey = ByteData{hex: tweakedPrivkey}
	}
	return pubkey, parity, privkey, err
}

// TweakAddPubkey This function return a schnorr's pubkey.
func (obj *SchnorrUtil) TweakAddPubkey(key, tweak ByteData) (pubkey ByteData, parity bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var tweakedPubkey string
	ret := CfdSchnorrPubkeyTweakAdd(handle, key.ToHex(), tweak.ToHex(), &tweakedPubkey, &parity)
	err = convertCfdError(ret, handle)
	if err == nil {
		pubkey = ByteData{hex: tweakedPubkey}
	}
	return pubkey, parity, err
}

// IsTweakedPubkey This function return a tweaked flag.
func (obj *SchnorrUtil) IsTweakedPubkey(key ByteData, parity bool, basePubkey, tweak ByteData) (isTweaked bool, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdCheckTweakAddFromSchnorrPubkey(handle, key.ToHex(), parity, basePubkey.ToHex(), tweak.ToHex())
	if ret == (int)(KCfdSuccess) {
		isTweaked = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isTweaked = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isTweaked, err
}

// Sign This function return a schnorr's signature.
func (obj *SchnorrUtil) Sign(msg, secretKey, auxRand ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrSignature string
	ret := CfdSignSchnorr(handle, msg.ToHex(), secretKey.ToHex(), auxRand.ToHex(), &schnorrSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: schnorrSignature}
	}
	return signature, err
}

// SignWithNonce This function return a schnorr's signature with nonce.
func (obj *SchnorrUtil) SignWithNonce(msg, secretKey, nonce ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrSignature string
	ret := CfdSignSchnorrWithNonce(handle, msg.ToHex(), secretKey.ToHex(), nonce.ToHex(), &schnorrSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: schnorrSignature}
	}
	return signature, err
}

// ComputeSigPoint This function return a sig-point.
func (obj *SchnorrUtil) ComputeSigPoint(msg, nonce, pubkey ByteData) (sigPoint ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var point string
	ret := CfdComputeSchnorrSigPoint(handle, msg.ToHex(), nonce.ToHex(), pubkey.ToHex(), &point)
	err = convertCfdError(ret, handle)
	if err == nil {
		sigPoint = ByteData{hex: point}
	}
	return sigPoint, err
}

// Verify This function verify a schnorr's signature.
func (obj *SchnorrUtil) Verify(signature, msg, pubkey ByteData) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifySchnorr(handle, signature.ToHex(), msg.ToHex(), pubkey.ToHex())
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}

// SplitSignature This function return schnorr nonce and schnorr privkey.
func (obj *SchnorrUtil) SplitSignature(signature ByteData) (nonce, key ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var schnorrNonce string
	var privkey string
	ret := CfdSplitSchnorrSignature(handle, signature.ToHex(), &schnorrNonce, &privkey)
	err = convertCfdError(ret, handle)
	if err == nil {
		nonce = ByteData{hex: schnorrNonce}
		key = ByteData{hex: privkey}
	}
	return nonce, key, err
}

// AddSighashTypeInSignature This function return schnorr signature added sighashType.
func (obj *SchnorrUtil) AddSighashTypeInSignature(signature *ByteData, sighashType *SigHashType) (addedSighash *ByteData, err error) {
	if signature == nil || sighashType == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var newSignature string
	ret := CfdAddSighashTypeInSchnorrSignature(handle, signature.ToHex(), sighashType.GetValue(), sighashType.AnyoneCanPay, &newSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		addedSighash = &ByteData{hex: newSignature}
	}
	return addedSighash, err
}

// EcdsaAdaptorUtil This struct use for the accessing to ecdsa-adaptor function.
type EcdsaAdaptorUtil struct {
}

// NewEcdsaAdaptorUtil This function return a EcdsaAdaptorUtil.
func NewEcdsaAdaptorUtil() *EcdsaAdaptorUtil {
	return &EcdsaAdaptorUtil{}
}

// Sign This function return a ecdsa-adaptor's signature and proof.
func (obj *EcdsaAdaptorUtil) Sign(msg, secretKey, adaptor ByteData) (adaptorSignature, adaptorProof ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var signature string
	var proof string
	ret := CfdSignEcdsaAdaptor(handle, msg.ToHex(), secretKey.ToHex(), adaptor.ToHex(), &signature, &proof)
	err = convertCfdError(ret, handle)
	if err == nil {
		adaptorSignature = ByteData{hex: signature}
		adaptorProof = ByteData{hex: proof}
	}
	return adaptorSignature, adaptorProof, err
}

// Adapt This function return a decrypted signature.
func (obj *EcdsaAdaptorUtil) Adapt(adaptorSignature, adaptorSecret ByteData) (signature ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var ecSignature string
	ret := CfdAdaptEcdsaAdaptor(handle, adaptorSignature.ToHex(), adaptorSecret.ToHex(), &ecSignature)
	err = convertCfdError(ret, handle)
	if err == nil {
		signature = ByteData{hex: ecSignature}
	}
	return signature, err
}

// ExtractSecret This function return a adaptor secret.
func (obj *EcdsaAdaptorUtil) ExtractSecret(adaptorSignature, signature, adaptor ByteData) (secret ByteData, err error) {
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	var adaptorSecret string
	ret := CfdExtractEcdsaAdaptorSecret(handle, adaptorSignature.ToHex(), signature.ToHex(), adaptor.ToHex(), &adaptorSecret)
	err = convertCfdError(ret, handle)
	if err == nil {
		secret = ByteData{hex: adaptorSecret}
	}
	return secret, err
}

// Verify This function verify a ecdsa-adaptor's signature.
func (obj *EcdsaAdaptorUtil) Verify(adaptorSignature, adaptorProof, adaptor, msg, pubkey ByteData) (isVerify bool, err error) {
	isVerify = false
	handle, err := CfdGoCreateHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)

	ret := CfdVerifyEcdsaAdaptor(handle, adaptorSignature.ToHex(), adaptorProof.ToHex(), adaptor.ToHex(), msg.ToHex(), pubkey.ToHex())
	if ret == (int)(KCfdSuccess) {
		isVerify = true
	} else if ret == (int)(KCfdSignVerificationError) {
		isVerify = false
	} else {
		err = convertCfdError(ret, handle)
	}
	return isVerify, err
}
