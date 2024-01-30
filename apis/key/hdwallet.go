package key

import (
	"strconv"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

const (
	Bip32PubkeyVersionMainnet string = "0488b21e"
	Bip49PubkeyVersionMainnet string = "049d7cb2"
	Bip84PubkeyVersionMainnet string = "04b24746"
	Bip32PubkeyVersionTestnet string = "043587cf"
	Bip49PubkeyVersionTestnet string = "044a5262"
	Bip84PubkeyVersionTestnet string = "045f1cf6"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate go run go.uber.org/mock/mockgen@v0.4.0 -source hdwallet.go -destination mock/hdwallet.go -package mock
//go:generate go run golang.org/x/tools/cmd/goimports@v0.17.0 -w mock/hdwallet.go

// FIXME split file

type Bip32Item func() string

// Bip32ByNum returns Bip32Item function.
func Bip32ByNum(value int) Bip32Item {
	return func() string {
		if value < 0 {
			val := value & 0x7fffffff
			return strconv.Itoa(val) + "'"
		}
		return strconv.Itoa(value)
	}
}

// HardenedBip32ByNum returns Bip32Item function.
func HardenedBip32ByNum(value int) Bip32Item {
	return func() string {
		val := value & 0x7fffffff
		return strconv.Itoa(val) + "'"
	}
}

// Bip32ByString returns Bip32Item function.
func Bip32ByString(value string) Bip32Item {
	return func() string {
		numStr := value
		var hardenedStr string
		switch {
		case strings.HasSuffix(value, "h"), strings.HasSuffix(value, "'"):
			hardenedStr = value[len(value)-1:]
			numStr = value[:len(value)-1]
		default:
		}
		num, err := strconv.ParseInt(numStr, 0, 32)
		if err != nil || num < 0 {
			return ""
		}
		return numStr + hardenedStr
	}
}

// Bip32Root returns Bip32Item function.
func Bip32Root() Bip32Item {
	return func() string {
		return "m"
	}
}

type ExtPubkeyApi interface {
	GetPubkey(extPubkey *types.ExtPubkey) (pubkey *types.Pubkey, err error)
	// GetExtPubkeyByPath ...
	GetExtPubkeyByPath(extPubkey *types.ExtPubkey, bip32Path string) (derivedPubkey *types.ExtPubkey, err error)
	GetData(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error)
	// ConvertToBip32 ...
	ConvertToBip32(extPubkey *types.ExtPubkey) (bip32ExtPubkey *types.ExtPubkey, err error)
}

type ExtPrivkeyApi interface {
	GetPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.Pubkey, err error)
	GetPrivkey(extPrivkey *types.ExtPrivkey) (privkey *types.Privkey, err error)
	GetExtPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.ExtPubkey, err error)
	GetExtPrivkeyByPath(extPrivkey *types.ExtPrivkey, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error)
	GetData(extPrivkey *types.ExtPrivkey) (data *types.ExtkeyData, err error)
}

type HdWalletApi interface {
	GetExtPrivkey(seed *types.ByteData) (privkey *types.ExtPrivkey, err error)
	GetExtPrivkeyByPath(seed *types.ByteData, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error)
	GetExtPubkeyByPath(seed *types.ByteData, bip32Path string) (derivedPubkey *types.ExtPubkey, err error)
	GetExtPrivkeyWithFormat(seed *types.ByteData, formatType types.ExtkeyFormatType) (privkey *types.ExtPrivkey, err error)
	GetExtPrivkeyByPathWithFormat(seed *types.ByteData, bip32Path string, formatType types.ExtkeyFormatType) (derivedPrivkey *types.ExtPrivkey, err error)
	GetExtPubkeyByPathWithFormat(seed *types.ByteData, bip32Path string, formatType types.ExtkeyFormatType) (derivedPubkey *types.ExtPubkey, err error)
	GetSeedFromMnemonicEng(mnemonic []string) (seed *types.ByteData, entropy *types.ByteData, err error)
	GetSeedFromMnemonicEngAndPassphrase(mnemonic []string, passphrase string) (seed *types.ByteData, entropy *types.ByteData, err error)
	GetMnemonicFromEntropyEng(entropy *types.ByteData) (mnemonic *[]string, err error)
	GetSeedFromMnemonic(mnemonic []string, language string) (seed *types.ByteData, entropy *types.ByteData, err error)
	GetSeedFromMnemonicAndPassphrase(mnemonic []string, language string, passphrase string) (seed *types.ByteData, entropy *types.ByteData, err error)
	GetMnemonicFromEntropy(entropy *types.ByteData, language string) (mnemonic *[]string, err error)
	CreateBip32Path(items ...Bip32Item) (path string, err error)
}

func NewExtPubkeyApi(options ...config.CfdConfigOption) *ExtPubkeyApiImpl {
	api := ExtPubkeyApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

func NewExtPrivkeyApi(options ...config.CfdConfigOption) *ExtPrivkeyApiImpl {
	api := ExtPrivkeyApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

func NewHdWalletApi(options ...config.CfdConfigOption) *HdWalletApiImpl {
	api := HdWalletApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

// -------------------------------------
// struct
// -------------------------------------

type ExtPubkeyApiImpl struct {
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

type ExtPrivkeyApiImpl struct {
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

type HdWalletApiImpl struct {
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

// -------------------------------------
// implement ExtPubkey
// -------------------------------------

// GetPubkey ...
func (k *ExtPubkeyApiImpl) GetPubkey(extPubkey *types.ExtPubkey) (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPubkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(extPubkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "get pubkey error")
	}
	pubkey = &types.Pubkey{Hex: hex}
	return pubkey, nil
}

// GetExtPubkeyByPath ...
func (k *ExtPubkeyApiImpl) GetExtPubkeyByPath(extPubkey *types.ExtPubkey, bip32Path string) (derivedPubkey *types.ExtPubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPubkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	child, err := cfd.CfdGoCreateExtkeyFromParentPath(extPubkey.Key, bip32Path, k.network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, errors.Wrap(err, "derive extkey error")
	}
	derivedPubkey = &types.ExtPubkey{Key: child}
	return derivedPubkey, nil
}

// GetData ...
func (k *ExtPubkeyApiImpl) GetData(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if data, err = k.validExtkeyInfo(extPubkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	return data, nil
}

// Valid ...
func (k *ExtPubkeyApiImpl) Valid(extPubkey *types.ExtPubkey) error {
	if err := k.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if _, err := k.validExtkeyInfo(extPubkey); err != nil {
		return errors.Wrap(err, "validate extkey error")
	}
	return nil
}

// ConvertToBip32 ...
func (k *ExtPubkeyApiImpl) ConvertToBip32(extPubkey *types.ExtPubkey) (bip32ExtPubkey *types.ExtPubkey, err error) {
	prefix := ""
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if extPubkey == nil {
		return nil, errors.Errorf("CFD Error: extPubkey is nil")
	} else if strings.HasPrefix(extPubkey.Key, "zpub") || strings.HasPrefix(extPubkey.Key, "ypub") {
		prefix = "0488b21e" // mainnet
	} else if strings.HasPrefix(extPubkey.Key, "vpub") || strings.HasPrefix(extPubkey.Key, "upub") {
		prefix = "043587cf" // testnet/regtest
	} else {
		return extPubkey, nil
	}
	base58Data, err := cfd.CfdGoDecodeBase58(extPubkey.Key, true)
	if err != nil {
		return nil, errors.Wrap(err, "DecodeBase58 failed")
	}
	key, err := cfd.CfdGoEncodeBase58(prefix+base58Data[8:], true)
	if err != nil {
		return nil, errors.Wrap(err, "EncodeBase58 failed")
	}
	bip32ExtPubkey = &types.ExtPubkey{Key: key}
	return bip32ExtPubkey, nil
}

// validExtkeyInfo ...
func (k *ExtPubkeyApiImpl) validExtkeyInfo(extPubkey *types.ExtPubkey) (data *types.ExtkeyData, err error) {
	if extPubkey == nil {
		return nil, errors.Errorf("CFD Error: extPubkey is nil")
	}
	data, err = getExtkeyInformationInternal(extPubkey.Key)
	if err != nil {
		return nil, errors.Wrap(err, "parse extprivkey error")
	} else if data.KeyType != types.ExtPubkeyType {
		return nil, errors.Errorf("CFD Error: This extkey is privkey")
	} else if k.network.ToBitcoinType().IsMainnet() != data.Network.IsMainnet() {
		return nil, errors.Errorf("CFD Error: Unmatch network type on extpubkey")
	}
	return data, nil
}

// validConfig ...
func (k *ExtPubkeyApiImpl) validConfig() error {
	if k.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !k.network.IsBitcoin() {
		return cfdErrors.ErrBitcoinNetwork
	}
	return nil
}

// -------------------------------------
// implement ExtPrivkey
// -------------------------------------

// GetPubkey ...
func (k *ExtPrivkeyApiImpl) GetPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.Pubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPrivkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	hex, err := cfd.CfdGoGetPubkeyFromExtkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "get pubkey error")
	}
	pubkey = &types.Pubkey{Hex: hex}
	return pubkey, nil
}

// GetPrivkey
func (k *ExtPrivkeyApiImpl) GetPrivkey(extPrivkey *types.ExtPrivkey) (privkey *types.Privkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPrivkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	hex, wif, err := cfd.CfdGoGetPrivkeyFromExtkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "get privkey error")
	}
	privkey = &types.Privkey{
		Hex:                hex,
		Wif:                wif,
		Network:            *k.network,
		IsCompressedPubkey: true,
	}
	return privkey, nil
}

// GetExtPubkey
func (k *ExtPrivkeyApiImpl) GetExtPubkey(extPrivkey *types.ExtPrivkey) (pubkey *types.ExtPubkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPrivkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	key, err := cfd.CfdGoCreateExtPubkey(extPrivkey.Key, k.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "get extpubkey error")
	}
	pubkey = &types.ExtPubkey{Key: key}
	return pubkey, nil
}

func (k *ExtPrivkeyApiImpl) GetExtPrivkeyByPath(extPrivkey *types.ExtPrivkey, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if _, err = k.validExtkeyInfo(extPrivkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	key, err := cfd.CfdGoCreateExtkeyFromParentPath(extPrivkey.Key, bip32Path, k.network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPrivkey))
	if err != nil {
		return nil, errors.Wrap(err, "derive extkey error")
	}
	derivedPrivkey = &types.ExtPrivkey{Key: key}
	return derivedPrivkey, nil
}

// GetData ...
func (k *ExtPrivkeyApiImpl) GetData(extPrivkey *types.ExtPrivkey) (data *types.ExtkeyData, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if data, err = k.validExtkeyInfo(extPrivkey); err != nil {
		return nil, errors.Wrap(err, "validate extkey error")
	}
	return data, nil
}

// Valid ...
func (k *ExtPrivkeyApiImpl) Valid(extPrivkey *types.ExtPrivkey) error {
	if err := k.validConfig(); err != nil {
		return errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if _, err := k.validExtkeyInfo(extPrivkey); err != nil {
		return errors.Wrap(err, "validate extkey error")
	}
	return nil
}

// validExtkeyInfo ...
func (k *ExtPrivkeyApiImpl) validExtkeyInfo(extPrivkey *types.ExtPrivkey) (data *types.ExtkeyData, err error) {
	if extPrivkey == nil {
		return nil, errors.Errorf("CFD Error: extPrivkey is nil")
	}
	data, err = getExtkeyInformationInternal(extPrivkey.Key)
	if err != nil {
		return nil, errors.Wrap(err, "parse extprivkey error")
	} else if data.KeyType != types.ExtPrivkeyType {
		return nil, errors.Errorf("CFD Error: This extkey is pubkey")
	} else if k.network.ToBitcoinType().IsMainnet() != data.Network.IsMainnet() {
		return nil, errors.Errorf("CFD Error: Unmatch network type on extprivkey")
	}
	return data, nil
}

// validConfig ...
func (k *ExtPrivkeyApiImpl) validConfig() error {
	if k.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !k.network.IsBitcoin() {
		return cfdErrors.ErrBitcoinNetwork
	}
	return nil
}

// -------------------------------------
// implement HdWalletApiImpl
// -------------------------------------
func (h *HdWalletApiImpl) GetExtPrivkey(seed *types.ByteData) (privkey *types.ExtPrivkey, err error) {
	return h.GetExtPrivkeyWithFormat(seed, types.ExtkeyFormatTypeBip32)
}

func (h *HdWalletApiImpl) GetExtPrivkeyByPath(seed *types.ByteData, bip32Path string) (derivedPrivkey *types.ExtPrivkey, err error) {
	return h.GetExtPrivkeyByPathWithFormat(seed, bip32Path, types.ExtkeyFormatTypeBip32)
}

func (h *HdWalletApiImpl) GetExtPubkeyByPath(seed *types.ByteData, bip32Path string) (derivedPubkey *types.ExtPubkey, err error) {
	return h.GetExtPubkeyByPathWithFormat(seed, bip32Path, types.ExtkeyFormatTypeBip32)
}

func (h *HdWalletApiImpl) GetExtPrivkeyWithFormat(seed *types.ByteData, formatType types.ExtkeyFormatType) (privkey *types.ExtPrivkey, err error) {
	if err := h.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if seed == nil {
		return nil, errors.Errorf("CFD Error: seed is nil")
	}
	key, err := cfd.CfdGoCreateExtkeyByFormatFromSeed(seed.ToHex(), h.network.ToCfdValue(), int(cfd.KCfdExtPrivkey), formatType.ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create extkey error")
	}
	privkey = &types.ExtPrivkey{Key: key}
	return privkey, nil
}

func (h *HdWalletApiImpl) GetExtPrivkeyByPathWithFormat(seed *types.ByteData, bip32Path string, formatType types.ExtkeyFormatType) (derivedPrivkey *types.ExtPrivkey, err error) {
	privkey, err := h.GetExtPrivkeyWithFormat(seed, formatType)
	if err != nil {
		return nil, errors.Wrap(err, "get extprivkey error")
	}
	key, err := cfd.CfdGoCreateExtkeyFromParentPath(privkey.Key, bip32Path, h.network.ToCfdValue(), int(cfd.KCfdExtPrivkey))
	if err != nil {
		return nil, errors.Wrap(err, "derive extkey error")
	}
	derivedPrivkey = &types.ExtPrivkey{Key: key}
	return derivedPrivkey, nil
}

func (h *HdWalletApiImpl) GetExtPubkeyByPathWithFormat(seed *types.ByteData, bip32Path string, formatType types.ExtkeyFormatType) (derivedPubkey *types.ExtPubkey, err error) {
	privkey, err := h.GetExtPrivkeyWithFormat(seed, formatType)
	if err != nil {
		return nil, errors.Wrap(err, "get extprivkey error")
	}
	key, err := cfd.CfdGoCreateExtkeyFromParentPath(privkey.Key, bip32Path, h.network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, errors.Wrap(err, "derive extkey error")
	}
	derivedPubkey = &types.ExtPubkey{Key: key}
	return derivedPubkey, nil
}

func (h *HdWalletApiImpl) GetSeedFromMnemonicEng(mnemonic []string) (seed *types.ByteData, entropy *types.ByteData, err error) {
	seed, entropy, err = h.GetSeedFromMnemonic(mnemonic, "en")
	return seed, entropy, err
}

func (h *HdWalletApiImpl) GetSeedFromMnemonicEngAndPassphrase(mnemonic []string, passphrase string) (seed *types.ByteData, entropy *types.ByteData, err error) {
	seed, entropy, err = h.GetSeedFromMnemonicAndPassphrase(mnemonic, "en", passphrase)
	return seed, entropy, err
}

func (h *HdWalletApiImpl) GetMnemonicFromEntropyEng(entropy *types.ByteData) (mnemonic *[]string, err error) {
	mnemonic, err = h.GetMnemonicFromEntropy(entropy, "en")
	return mnemonic, err
}

func (h *HdWalletApiImpl) GetSeedFromMnemonic(mnemonic []string, language string) (seed *types.ByteData, entropy *types.ByteData, err error) {
	seed, entropy, err = h.GetSeedFromMnemonicAndPassphrase(mnemonic, language, "")
	return seed, entropy, err
}

func (h *HdWalletApiImpl) GetSeedFromMnemonicAndPassphrase(mnemonic []string, language string, passphrase string) (seed *types.ByteData, entropy *types.ByteData, err error) {
	if err := h.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if (mnemonic == nil) || (len(mnemonic) == 0) {
		return nil, nil, errors.Errorf("CFD Error: mnemonic is nil or empty")
	}
	seedHex, entropyHex, err := cfd.CfdGoConvertMnemonicWordsToSeed(mnemonic, passphrase, language)
	if err != nil {
		return nil, nil, errors.Wrap(err, "mnemonic to seed error")
	}
	seed = types.NewByteDataFromHexIgnoreError(seedHex)
	entropy = types.NewByteDataFromHexIgnoreError(entropyHex)
	return seed, entropy, nil
}

func (h *HdWalletApiImpl) GetMnemonicFromEntropy(entropy *types.ByteData, language string) (mnemonic *[]string, err error) {
	if err := h.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if entropy == nil {
		return nil, errors.Errorf("CFD Error: entropy is nil")
	}
	mnemonicText, err := cfd.CfdGoConvertEntropyToMnemonic(entropy.ToHex(), language)
	if err != nil {
		return nil, errors.Wrap(err, "mnemonic from entropy error")
	}
	mnemonicWords := strings.Split(mnemonicText, " ")
	mnemonic = &mnemonicWords
	return mnemonic, nil
}

func (h *HdWalletApiImpl) CreateBip32Path(items ...Bip32Item) (path string, err error) {
	bip32Path := ""
	for i, itemFunc := range items {
		pathStr := itemFunc()
		if pathStr == "" {
			return "", errors.Errorf("CFD Error: invalid path")
		} else if pathStr == "m" && i != 0 {
			return "", errors.Errorf("CFD Error: invalid root item position")
		}
		if bip32Path != "" {
			bip32Path += "/"
		}
		bip32Path += pathStr
	}
	return bip32Path, nil
}

// validConfig ...
func (h *HdWalletApiImpl) validConfig() error {
	if h.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !h.network.IsBitcoin() {
		return cfdErrors.ErrBitcoinNetwork
	}
	return nil
}

// internal --------------------------------------------------------------------

func getExtkeyInformationInternal(key string) (data *types.ExtkeyData, err error) {
	tempData, keyType, netType, err := cfd.CfdGoGetExtkeyInfo(key)
	if err != nil {
		return nil, errors.Wrap(err, "parse extkey error")
	}
	data = &types.ExtkeyData{
		Version:     tempData.Version,
		Fingerprint: tempData.Fingerprint,
		Depth:       tempData.Depth,
		ChildNumber: tempData.ChildNumber,
		ChainCode:   tempData.ChainCode,
		KeyType:     types.NewExtkeyType(keyType),
		Network:     types.NewNetworkType(netType),
	}
	return data, nil
}
