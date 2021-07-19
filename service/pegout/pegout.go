package pegout

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

// Pegout This interface defines the API used by the pegout function.
type Pegout interface {
	// CreateOnlinePrivateKey This function generate random private key for online key.
	CreateOnlinePrivateKey() (privkey *types.Privkey, err error)
	// CreatePakEntry This function create the PAK-Entry.
	CreatePakEntry(
		accountExtPubkey *types.ExtPubkey,
		onlinePrivkey *types.Privkey,
	) (pakEntry *types.ByteData, err error)
	// CreatePegoutAddress This function create the pegout address for bitcoin network.
	CreatePegoutAddress(
		addressType types.AddressType,
		accountExtPubkey *types.ExtPubkey,
		addressIndex uint32,
	) (pegoutAddress *types.Address, baseDescriptor *types.Descriptor, err error)
	// CreatePegoutTransaction This function create the pegout transaction.
	CreatePegoutTransaction(
		utxoList []types.ElementsUtxoData,
		pegoutData types.InputConfidentialTxOut,
		sendList *[]types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.PegoutTxOption,
	) (
		tx *types.ConfidentialTx,
		pegoutAddress *types.Address,
		unblindTx *types.ConfidentialTx,
		err error,
	)
	// VerifyPubkeySignature This function validate the signature by pubkey.
	VerifyPubkeySignature(
		proposalTx *types.ConfidentialTx,
		utxoData *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
}

// NewPegoutService returns an object that defines the API for Pegout.
func NewPegoutService(options ...config.CfdConfigOption) *PegoutService {
	service := PegoutService{}
	var err error
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		service.setError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsElements() {
		service.setError(cfdErrors.ElementsNetworkError)
	} else {
		network = conf.Network
	}

	var bitcoinAssetId *types.ByteData
	if len(conf.BitcoinAssetId) != 0 {
		if bitcoinAssetId, err = utils.ValidAssetId(conf.BitcoinAssetId); err != nil {
			service.setError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}
	var bitcoinGenesisBlockHash *types.ByteData
	if len(conf.BitcoinGenesisBlockHash) != 0 {
		if bitcoinGenesisBlockHash, err = utils.ValidBlockHash(conf.BitcoinGenesisBlockHash); err != nil {
			service.setError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}

	if network.Valid() {
		service.network = &network
		service.bitcoinAssetId = bitcoinAssetId
		service.bitcoinGenesisBlockHash = bitcoinGenesisBlockHash

		elementsConfOpts := service.getConfig().GetOptions()
		descriptorApi := descriptor.NewDescriptorApi(elementsConfOpts...)
		if descriptorApi.InitializeError != nil {
			service.setError(descriptorApi.InitializeError)
		} else {
			service.descriptorApi = descriptorApi
		}

		txApi := transaction.NewConfidentialTxApi(elementsConfOpts...)
		if txApi.InitializeError != nil {
			service.setError(txApi.InitializeError)
		} else {
			service.elementsTxApi = txApi
		}

		btcNetworkOpt := config.NetworkOpt(network.ToBitcoinType())
		bitcoinAddrApi := address.NewAddressApi(btcNetworkOpt)
		if bitcoinAddrApi.InitializeError != nil {
			service.setError(bitcoinAddrApi.InitializeError)
		} else {
			service.bitcoinAddressApi = bitcoinAddrApi
		}

		service.pubkeyApi = key.NewPubkeyApi()
	}
	return &service
}

// -------------------------------------
// PegoutService
// -------------------------------------

// PegoutService This struct is implements pegout api.
type PegoutService struct {
	InitializeError         error
	network                 *types.NetworkType
	bitcoinGenesisBlockHash *types.ByteData
	bitcoinAssetId          *types.ByteData
	bitcoinAddressApi       address.AddressApi
	elementsTxApi           transaction.ConfidentialTxApi
	descriptorApi           descriptor.DescriptorApi
	pubkeyApi               key.PubkeyApi
}

// WithElementsDescriptorApi This function set a elements descriptor api.
func (p *PegoutService) WithElementsDescriptorApi(descriptorApi descriptor.DescriptorApi) *PegoutService {
	if descriptorApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else if !utils.ValidNetworkTypes(descriptorApi.GetNetworkTypes(), types.LiquidV1) {
		p.setError(cfdErrors.ElementsNetworkError)
	} else {
		p.descriptorApi = descriptorApi
	}
	return p
}

// WithBitcoinAddressApi This function set a bitcoin address api.
func (p *PegoutService) WithBitcoinAddressApi(addressApi address.AddressApi) *PegoutService {
	if addressApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else if !utils.ValidNetworkTypes(addressApi.GetNetworkTypes(), types.Mainnet) {
		p.setError(cfdErrors.ElementsNetworkError)
	} else {
		p.bitcoinAddressApi = addressApi
	}
	return p
}

// WithConfidentialTxApi This function set a confidential transaction api.
func (p *PegoutService) WithConfidentialTxApi(confidentialTxApi transaction.ConfidentialTxApi) *PegoutService {
	if confidentialTxApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else {
		p.elementsTxApi = confidentialTxApi
	}
	return p
}

// WithPubkeyApi This function set a pubkey api.
func (p *PegoutService) WithPubkeyApi(pubkeyApi key.PubkeyApi) *PegoutService {
	if pubkeyApi == nil {
		p.setError(cfdErrors.ParameterNilError)
	} else {
		p.pubkeyApi = pubkeyApi
	}
	return p
}

func (p *PegoutService) setError(err error) {
	if err == nil {
		return
	}
	multiError, ok := p.InitializeError.(*cfdErrors.MultiError)
	if !ok {
		multiError = cfdErrors.NewMultiError(
			cfdErrors.CfdError("CFD Error: PegoutService initialize error"))
	}
	multiError.Add(err)
	p.InitializeError = multiError
}

// CreateOnlinePrivateKey This function generate random private key for online key.
func (p *PegoutService) CreateOnlinePrivateKey() (privkey *types.Privkey, err error) {
	if err = p.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	_, privkeyHex, wif, err := cfd.CfdGoCreateKeyPair(true, p.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create keyPair error")
	}
	privkey = &types.Privkey{
		Hex:                privkeyHex,
		Wif:                wif,
		Network:            *p.network,
		IsCompressedPubkey: true,
	}
	return privkey, nil
}

// CreatePakEntry This function create the PAK-Entry.
func (p *PegoutService) CreatePakEntry(
	accountExtPubkey *types.ExtPubkey,
	onlinePrivkey *types.Privkey,
) (pakEntry *types.ByteData, err error) {
	if err = p.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if err = validatePegoutExtPubkey(accountExtPubkey); err != nil {
		return nil, errors.Wrap(err, "Pegout validate accountExtPubkey error")
	} else if err = validateOnlinePrivkey(onlinePrivkey, p.network.ToBitcoinType()); err != nil {
		return nil, errors.Wrap(err, "Pegout validate onlinePrivkey error")
	}

	offlinePubkey, err := cfd.CfdGoGetPubkeyFromExtkey(accountExtPubkey.Key, p.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "Pegout get pubkey error")
	}
	offlineNegatePubkey, err := cfd.CfdGoNegatePubkey(offlinePubkey)
	if err != nil {
		return nil, errors.Wrap(err, "Pegout negate pubkey error")
	}

	var onlinePubkey string
	if len(onlinePrivkey.Wif) > 0 {
		onlinePubkey, err = cfd.CfdGoGetPubkeyFromPrivkey("", onlinePrivkey.Wif, true)
	} else {
		onlinePubkey, err = cfd.CfdGoGetPubkeyFromPrivkey(onlinePrivkey.Hex, "", true)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Pegout get privkey's pubkey error")
	}
	pakEntryObj, err := types.NewByteDataFromHex(offlineNegatePubkey + onlinePubkey)
	if err != nil {
		return nil, errors.Wrap(err, "Pegout internal error")
	}
	pakEntry = &pakEntryObj
	return pakEntry, nil
}

// CreatePegoutAddress This function create the pegout address for bitcoin network.
func (p *PegoutService) CreatePegoutAddress(
	addressType types.AddressType,
	accountExtPubkey *types.ExtPubkey,
	addressIndex uint32,
) (pegoutAddress *types.Address, baseDescriptor *types.Descriptor, err error) {
	if err = p.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	desc := ""
	switch addressType {
	case types.P2pkhAddress:
		desc = "pkh("
	case types.P2wpkhAddress:
		desc = "wpkh("
	case types.P2shP2wpkhAddress:
		desc = "sh(wpkh("
	default:
		return nil, nil, errors.Errorf("CFD Error: Invalid pegout address type")
	}
	if err = validatePegoutExtPubkey(accountExtPubkey); err != nil {
		return nil, nil, errors.Wrap(err, "validate pegout extkey error")
	} else if addressIndex >= 0x80000000 {
		return nil, nil, errors.Errorf("CFD Error: Invalid account index. The hardened index can not used on the pegout")
	}

	address, _, err := cfd.CfdGoGetPegoutAddress(p.network.ToBitcoinType().ToCfdValue(), p.network.ToCfdValue(), accountExtPubkey.Key, addressIndex, addressType.ToCfdValue())
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegout address error")
	}
	if addressType == types.P2shP2wpkhAddress {
		desc = desc + accountExtPubkey.Key + "))"
	} else {
		desc = desc + accountExtPubkey.Key + ")"
	}
	pegoutAddress = &types.Address{
		Address: address,
		Network: p.network.ToBitcoinType(),
		Type:    addressType,
	}
	baseDescriptor = &types.Descriptor{
		OutputDescriptor: desc,
	}
	return pegoutAddress, baseDescriptor, nil
}

// CreatePegoutTransaction This function create the pegout transaction.
func (p *PegoutService) CreatePegoutTransaction(
	utxoList []types.ElementsUtxoData,
	pegoutData types.InputConfidentialTxOut,
	sendList *[]types.InputConfidentialTxOut,
	changeAddress *string,
	option *types.PegoutTxOption,
) (tx *types.ConfidentialTx, pegoutAddress *types.Address, unblindTx *types.ConfidentialTx, err error) {
	if err = p.validConfig(); err != nil {
		return nil, nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	// validation utxoList, pegoutData
	if err = p.validateUtxoList(&utxoList); err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout utxoList validation error")
	} else if err = p.validatePegoutData(&pegoutData); err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout peginData validation error")
	}

	workPegoutData := pegoutData
	workPegoutInput := *pegoutData.PegoutInput
	workPegoutData.PegoutInput = &workPegoutInput
	if (len(workPegoutInput.BitcoinGenesisBlockHash) != 64) && (p.bitcoinGenesisBlockHash != nil) {
		workPegoutInput.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	if (len(workPegoutData.Asset) != 64) && (p.bitcoinAssetId != nil) {
		workPegoutData.Asset = p.bitcoinAssetId.ToHex()
	}
	assetId := workPegoutData.Asset

	changeAddr, err := p.validateChangeAddress(changeAddress)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout changeAddress validation error")
	}

	blindOutputCount, hasAppendDummyOutput, amount, err := p.validateTxInOutList(&utxoList, sendList, changeAddr)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout sendList validation error")
	}
	if option.IsBlindTx && (blindOutputCount == 0) {
		return nil, nil, nil, errors.Wrap(err, "Pegout sendList empty blinding output error")
	} else if !option.IsBlindTx && (blindOutputCount > 0) {
		return nil, nil, nil, errors.Wrap(err, "Pegout sendList exist blinding output error")
	}

	// 1. create transaction
	sendListNum := 0
	if sendList != nil {
		sendListNum = len(*sendList)
	}
	txins := []types.InputConfidentialTxIn{}
	txouts := make([]types.InputConfidentialTxOut, sendListNum+1)
	txouts[0].Asset = assetId
	txouts[0].Amount = workPegoutData.Amount
	txouts[0].PegoutInput = workPegoutData.PegoutInput
	if sendList != nil {
		for i, output := range *sendList {
			txouts[i+1] = output
		}
	}
	pegoutAddrList := []string{}
	tx, err = p.elementsTxApi.Create(uint32(2), uint32(0), &txins, &txouts, &pegoutAddrList)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout CT.Create error")
	} else if len(pegoutAddrList) != 1 {
		return nil, nil, nil, errors.Wrap(err, "Pegout CT.Create pegoutAddress error")
	}
	pegoutAddress, err = p.bitcoinAddressApi.ParseAddress(pegoutAddrList[0])
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout parse address error")
	}

	// 2. add txout by output if single output.
	if hasAppendDummyOutput {
		// TODO Is this really a necessary process? I feel like it should be integrated with the subsequent process.
		tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.network)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "Pegout append dummy output error")
		}
	}

	// 3. fundrawtransaction
	fundTxInList := []cfd.CfdUtxo{}
	utxoListLen := len(utxoList)
	fundUtxoList := make([]cfd.CfdUtxo, utxoListLen)
	utxoMap := make(map[types.OutPoint]*types.ElementsUtxoData, utxoListLen)
	blindedUtxoMap := make(map[types.OutPoint]*types.ElementsUtxoData, utxoListLen)
	for i, txin := range utxoList {
		fundUtxoList[i].Txid = txin.OutPoint.Txid
		fundUtxoList[i].Vout = txin.OutPoint.Vout
		fundUtxoList[i].Amount = txin.Amount
		fundUtxoList[i].Asset = txin.Asset
		fundUtxoList[i].Descriptor = txin.Descriptor
		fundUtxoList[i].AmountCommitment = txin.AmountCommitment
		utxoMap[txin.OutPoint] = &txin
		if txin.HasBlindUtxo() {
			blindedUtxoMap[txin.OutPoint] = &txin
		}
	}
	targetAmounts := []cfd.CfdFundRawTxTargetAmount{
		{
			Amount: 0,
			Asset:  assetId,
		},
	}
	if amount == 0 {
		targetAmounts[0].Amount = 1
	}
	if changeAddress != nil {
		targetAmounts[0].ReservedAddress = *changeAddress
	}
	fundOption := cfd.NewCfdFundRawTxOption(p.network.ToCfdValue())
	fundOption.FeeAsset = assetId
	fundOption.EffectiveFeeRate = option.EffectiveFeeRate
	fundOption.LongTermFeeRate = option.LongTermFeeRate
	fundOption.DustFeeRate = option.DustFeeRate
	fundOption.IsBlindTx = option.IsBlindTx
	fundOption.KnapsackMinChange = option.KnapsackMinChange
	fundOption.Exponent = option.Exponent
	fundOption.MinimumBits = option.MinimumBits
	outputTx, _, _, err := cfd.CfdGoFundRawTransaction(p.network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Pegout FundRawTransaction error (tx: %s)", tx.Hex)
	}

	// 4. check to need append dummy output
	_, inputs, outputs, err := p.elementsTxApi.GetAll(&types.ConfidentialTx{Hex: outputTx}, false)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Pegout GetTxAll error")
	}
	outputCount := len(outputs)
	if option.IsBlindTx && !hasAppendDummyOutput && (outputCount == 3) { // 3 = output + fee + pegout
		hasAllBlinded := true
		for _, input := range inputs {
			_, ok := blindedUtxoMap[input.OutPoint]
			if !ok {
				hasAllBlinded = false
				break
			}
		}
		if !hasAllBlinded {
			tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.network)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Pegout append dummy output error")
			}
			outputTx, _, _, err = cfd.CfdGoFundRawTransaction(p.network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Pegout FundRawTransaction error")
			}
			_, inputs, _, err = p.elementsTxApi.GetAll(&types.ConfidentialTx{Hex: outputTx}, false)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Pegout GetTxAll error")
			}
		}
	}
	tx.Hex = outputTx

	// 5. blind
	unblindTx = &types.ConfidentialTx{Hex: tx.Hex}
	if option.IsBlindTx {
		blindInputList := make([]types.BlindInputData, len(inputs))
		for i, txin := range inputs {
			utxo, ok := utxoMap[txin.OutPoint]
			if !ok {
				return nil, nil, nil, errors.Errorf("CFD Error: Internal error")
			}
			blindInputList[i].OutPoint = txin.OutPoint
			blindInputList[i].Amount = utxo.Amount
			blindInputList[i].Asset = utxo.Asset
			blindInputList[i].ValueBlindFactor = utxo.ValueBlindFactor
			blindInputList[i].AssetBlindFactor = utxo.AssetBlindFactor
		}
		blindOption := types.NewBlindTxOption()
		blindOption.MinimumRangeValue = option.MinimumRangeValue
		blindOption.Exponent = option.Exponent
		blindOption.MinimumBits = option.MinimumBits
		err = p.elementsTxApi.Blind(tx, blindInputList, nil, &blindOption)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "Pegout Blind error: tx=%s", tx.Hex)
		}
	}

	return tx, pegoutAddress, unblindTx, nil
}

// VerifyPubkeySignature This function validate the signature by pubkey.
func (p *PegoutService) VerifyPubkeySignature(
	proposalTx *types.ConfidentialTx,
	utxoData *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	if err = p.validConfig(); err != nil {
		return false, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if proposalTx == nil || utxoData == nil || signature == nil {
		return false, cfdErrors.ParameterNilError
	} else if err = p.validateUtxoData(utxoData); err != nil {
		return false, errors.Wrap(err, "Pegout utxoData validate error")
	}

	sig, cfdSighashType, _, err := cfd.CfdGoDecodeSignatureFromDer(signature.ToHex())
	if err != nil {
		return false, errors.Wrap(err, "Pegout decode signature error")
	}
	sighashType := types.NewSigHashType(cfdSighashType)
	utxoList := []types.ElementsUtxoData{*utxoData}
	sighash, err := p.elementsTxApi.GetSighash(proposalTx, &utxoData.OutPoint, *sighashType, &utxoList)
	if err != nil {
		return false, errors.Wrap(err, "Pegout decode signature error")
	}
	desc := types.Descriptor{OutputDescriptor: utxoData.Descriptor}
	descData, _, _, err := p.descriptorApi.Parse(&desc)
	if err != nil {
		return false, errors.Wrap(err, "Pegout parse descriptor error")
	} else if descData.KeyType == int(cfd.KCfdDescriptorKeyNull) {
		return false, errors.Wrap(err, "Pegout descriptor unsupport key type")
	}
	pubkey := types.Pubkey{Hex: descData.Pubkey}
	return p.pubkeyApi.VerifyEcSignature(&pubkey, sighash.ToHex(), sig)
}

func (p *PegoutService) validConfig() error {
	if p.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !p.network.IsElements() {
		return cfdErrors.ElementsNetworkError
	}
	return nil
}

func (p *PegoutService) getConfig() *config.CfdConfig {
	conf := config.CfdConfig{Network: *p.network}
	if p.bitcoinAssetId != nil {
		conf.BitcoinAssetId = p.bitcoinAssetId.ToHex()
	}
	if p.bitcoinGenesisBlockHash != nil {
		conf.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	return &conf
}

func validateOnlinePrivkey(privkey *types.Privkey, network types.NetworkType) error {
	if privkey == nil {
		return errors.Errorf("CFD Error: Pegout privkey is nil")
	} else if privkey.Hex == "" && privkey.Wif == "" {
		return errors.Errorf("CFD Error: Pegout privkey is empty")
	} else if len(privkey.Wif) > 0 {
		keyApi := &key.PrivkeyApiImpl{}
		tmpPrivkey, err := keyApi.GetPrivkeyFromWif(privkey.Wif)
		if err != nil {
			return errors.Wrap(err, "wif convert error")
		} else if network.IsMainnet() != tmpPrivkey.Network.IsMainnet() {
			return errors.Errorf("CFD Error: Pegout privkey is invalid wif (mismatch networkType)")
		} else if !tmpPrivkey.IsCompressedPubkey {
			return errors.Errorf("CFD Error: Pegout privkey is invalid wif (not compressed flag)")
		}
	}
	return nil
}

func validatePegoutExtPubkey(extPubkey *types.ExtPubkey) error {
	if extPubkey == nil {
		return errors.Errorf("CFD Error: Pegout extkey is null")
	}
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return errors.Wrap(err, "extkey convert error")
	} else if data.Depth != 3 {
		return errors.Errorf("CFD Error: Invalid pegout extkey depth (%d)", data.Depth)
	}
	return nil
}

func (p *PegoutService) validateTxInOutList(utxoList *[]types.ElementsUtxoData, sendList *[]types.InputConfidentialTxOut, changeAddress *types.ConfidentialAddress) (blindOutputCount uint32, hasAppendDummyOutput bool, amount int64, err error) {
	caApi := address.ConfidentialAddressApiImpl{}
	blindOutputCount = uint32(0)
	unblindOutputCount := uint32(0)
	feeCount := uint32(0)
	blindInputCount := 0
	for _, txin := range *utxoList {
		if txin.HasBlindUtxo() {
			blindInputCount += 1
		}
	}
	hasAllInputBlinded := false
	if (blindInputCount > 0) && (blindInputCount == len(*utxoList)) {
		hasAllInputBlinded = true
	}

	if sendList != nil {
		for index, txout := range *sendList {
			isFee := false
			switch {
			case txout.PegoutInput != nil:
				return 0, false, 0, errors.Wrapf(err, "Pegout sendList exist pegout data error(n: %d)", index)
			case txout.IsFee:
				isFee = true
			case len(txout.Nonce) == types.CommitmentHexDataSize:
				if txout.IsDestroy || len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
					blindOutputCount += 1
					if txout.IsDestroy && (len(txout.LockingScript) > 0 || len(txout.Address) > 0) {
						return 0, false, 0, errors.Wrapf(err, "Pegout sendList invalid destroy amount error(n: %d)", index)
					}
				} else {
					return 0, false, 0, errors.Wrapf(err, "Pegout sendList invalid nonce error(n: %d)", index)
				}
			case txout.IsDestroy:
				if len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
					return 0, false, 0, errors.Wrapf(err, "Pegout sendList invalid destroy amount error(n: %d)", index)
				}
				unblindOutputCount += 1
			case len(txout.Address) > 0:
				addrInfo, err := caApi.Parse(txout.Address)
				if err != nil {
					return 0, false, 0, errors.Wrapf(err, "Pegout sendList address check error(n: %d)", index)
				} else if addrInfo.Network != *p.network {
					return 0, false, 0, errors.Wrapf(err, "Pegout sendList address network check error(n: %d)", index)
				} else if len(addrInfo.ConfidentialAddress) > 0 {
					blindOutputCount += 1
				} else {
					unblindOutputCount += 1
				}
			case len(txout.LockingScript) > 0:
				unblindOutputCount += 1
			default:
				isFee = true
			}

			if isFee {
				feeCount += 1
			} else {
				amount += txout.Amount
			}
		}
	}

	if changeAddress == nil {
		if blindOutputCount == 1 {
			hasAppendDummyOutput = true
		}
	} else if len(changeAddress.ConfidentialAddress) == 0 {
		if blindOutputCount > 0 {
			return 0, false, 0, errors.Wrap(err, "Pegout sendList mixed output error (changeAddress is blinded)")
		}
		unblindOutputCount += 1
	} else {
		blindOutputCount += 1
		if blindOutputCount == 1 {
			hasAppendDummyOutput = true
		}
	}

	if feeCount > 1 {
		return 0, false, 0, errors.Wrapf(err, "Pegout sendList fee output check error(count: %d)", feeCount)
	} else if (blindOutputCount == 0) && (unblindOutputCount == 0) {
		return 0, false, 0, errors.Wrap(err, "Pegout sendList output empty error")
	} else if (blindOutputCount > 0) && (unblindOutputCount > 0) {
		return 0, false, 0, errors.Wrap(err, "Pegout sendList mixed output error (blind & unblind)")
	}

	if hasAllInputBlinded && hasAppendDummyOutput {
		hasAppendDummyOutput = false
	}
	return blindOutputCount, hasAppendDummyOutput, amount, nil
}

func (p *PegoutService) validateUtxoList(utxoList *[]types.ElementsUtxoData) error {
	if utxoList != nil {
		for _, utxo := range *utxoList {
			switch {
			case len(utxo.OutPoint.Txid) != 64:
				return errors.Errorf("CFD Error: utxo OutPoint.Txid is invalid")
			case utxo.Amount == 0:
				return errors.Errorf("CFD Error: utxo Amount is invalid")
			case len(utxo.Asset) != 64:
				return errors.Errorf("CFD Error: utxo Amount is invalid")
			case (len(utxo.AssetBlindFactor) != 0) && (len(utxo.AssetBlindFactor) != 64):
				return errors.Errorf("CFD Error: utxo AssetBlindFactor is invalid")
			case (len(utxo.ValueBlindFactor) != 0) && (len(utxo.ValueBlindFactor) != 64):
				return errors.Errorf("CFD Error: utxo ValueBlindFactor is invalid")
			case len(utxo.Descriptor) == 0:
				return errors.Errorf("CFD Error: utxo Descriptor is invalid")
			case (len(utxo.AmountCommitment) != 0) && (len(utxo.AmountCommitment) != 66):
				return errors.Errorf("CFD Error: utxo AmountCommitment is invalid")
			case utxo.PeginData != nil:
				return errors.Errorf("CFD Error: Pegout utxo cannot use PeginData")
			case utxo.IsIssuance:
				return errors.Errorf("CFD Error: Pegout utxo cannot use IsIssuance")
			}
		}
	}
	return nil
}

func (p *PegoutService) validatePegoutData(pegoutData *types.InputConfidentialTxOut) error {
	switch {
	case pegoutData.PegoutInput == nil:
		return errors.Errorf("CFD Error: pegoutData.PegoutInput is nil")
	case pegoutData.Amount == 0:
		return errors.Errorf("CFD Error: pegoutData.Amount is 0")
	case pegoutData.IsDestroy:
		return errors.Errorf("CFD Error: pegoutData.IsDestroy cannot use")
	case pegoutData.IsFee:
		return errors.Errorf("CFD Error: pegoutData.IsFee cannot use")
	case len(pegoutData.Nonce) != 0:
		return errors.Errorf("CFD Error: pegoutData.Nonce is empty")
	case len(pegoutData.LockingScript) != 0:
		return errors.Errorf("CFD Error: pegoutData.LockingScript is empty")
	case len(pegoutData.PegoutInput.BitcoinOutputDescriptor) == 0:
		return errors.Errorf("CFD Error: pegoutData.PegoutInput.BitcoinOutputDescriptor is empty")
	case len(pegoutData.PegoutInput.OnlineKey) == 0:
		return errors.Errorf("CFD Error: pegoutData.PegoutInput.OnlineKey is empty")
	case len(pegoutData.PegoutInput.Whitelist) == 0:
		return errors.Errorf("CFD Error: pegoutData.PegoutInput.Whitelist is empty")
	}

	if (p.bitcoinGenesisBlockHash == nil) && (len(pegoutData.PegoutInput.BitcoinGenesisBlockHash) != 64) {
		return errors.Errorf("CFD Error: pegoutData.PegoutInput.BitcoinGenesisBlockHash is invalid")
	} else if (p.bitcoinAssetId == nil) && (len(pegoutData.Asset) != 64) {
		return errors.Errorf("CFD Error: pegoutData.Asset is invalid")
	}
	return nil
}

func (p *PegoutService) validateChangeAddress(changeAddress *string) (addr *types.ConfidentialAddress, err error) {
	caApi := address.ConfidentialAddressApiImpl{}
	if changeAddress != nil {
		addr, err = caApi.Parse(*changeAddress)
		if err != nil {
			return nil, errors.Wrap(err, "Pegout changeAddress error")
		} else if addr.Network != *p.network {
			return nil, errors.Wrap(err, "Pegout changeAddress network check error")
		}
		return addr, nil
	}
	return nil, nil
}

func (p *PegoutService) validateUtxoData(utxo *types.ElementsUtxoData) error {
	switch {
	case len(utxo.OutPoint.Txid) != 64:
		return errors.Errorf("CFD Error: utxo OutPoint.Txid is invalid")
	case utxo.Amount == 0:
		return errors.Errorf("CFD Error: utxo Amount is invalid")
	case len(utxo.Asset) != 64:
		return errors.Errorf("CFD Error: utxo Amount is invalid")
	case (len(utxo.AssetBlindFactor) != 0) && (len(utxo.AssetBlindFactor) != 64):
		return errors.Errorf("CFD Error: utxo AssetBlindFactor is invalid")
	case (len(utxo.ValueBlindFactor) != 0) && (len(utxo.ValueBlindFactor) != 64):
		return errors.Errorf("CFD Error: utxo ValueBlindFactor is invalid")
	case len(utxo.Descriptor) == 0:
		return errors.Errorf("CFD Error: utxo Descriptor is invalid")
	case (len(utxo.AmountCommitment) != 0) && (len(utxo.AmountCommitment) != 66):
		return errors.Errorf("CFD Error: utxo AmountCommitment is invalid")
	case utxo.IsIssuance:
		return errors.Errorf("CFD Error: Pegout utxo cannot use IsIssuance")
	default:
		return nil
	}
}

func appendDummyOutput(txHex string, assetId string, network *types.NetworkType) (outputTxHex string, err error) {
	// FIXME want to move this function to elements_tx.go.
	// generate random confidential key
	nonce, _, _, err := cfd.CfdGoCreateKeyPair(true, network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return "", errors.Wrap(err, "create keyPair error")
	}
	outputTxHex, err = cfd.CfdGoAddConfidentialTxOut(txHex, assetId, 0, "", "", "6a", nonce)
	if err != nil {
		return "", errors.Wrap(err, "add txout error")
	}
	return outputTxHex, nil
}
