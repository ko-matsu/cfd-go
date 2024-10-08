package script

import (
	"strconv"
	"strings"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"

	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate go run go.uber.org/mock/mockgen@v0.4.0 -source script.go -destination mock/script.go -package mock
//go:generate go run golang.org/x/tools/cmd/goimports@v0.17.0 -w mock/script.go

// -------------------------------------
// API struct
// -------------------------------------

const (
	MaxMultisigPubkeyNum     = 20
	MaxP2shMultisigPubkeyNum = 16
)

type ScriptApi interface {
	CreateFromAsm(asm string) (script *types.Script, err error)
	CreateFromAsmStrings(asmStrings []string) (script *types.Script, err error)
	Parse(script *types.Script) (asmStrings []string, err error)
	ParseMultisig(script *types.Script) (pubkey []*types.Pubkey, requireSigNum uint32, err error)
	CreateMultisig(pubkeys []*types.Pubkey, requireSigNum uint32) (script *types.Script, err error)
	AnalyzeLockingScript(script *types.Script) (hashType types.HashType, err error)
	IsCheckHashType(hashType types.HashType, script *types.Script) (bool, error)
}

// TODO(k-matsuzawa): Implement APIs for the following functions in the future.
// create tapscript
// parse tapscript

// NewScriptApi returns an object that defines the API for Script
func NewScriptApi() *ScriptApiImpl {
	api := ScriptApiImpl{}
	api.pubkeyApi = key.NewPubkeyApi()
	return &api
}

// -------------------------------------
// ScriptApiImpl
// -------------------------------------

type ScriptApiImpl struct {
	cfdErrors.HasInitializeError
	pubkeyApi key.PubkeyApi
}

// WithPubkeyApi This function set a pubkey api.
func (p *ScriptApiImpl) WithPubkeyApi(pubkeyApi key.PubkeyApi) *ScriptApiImpl {
	if pubkeyApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else {
		p.pubkeyApi = pubkeyApi
	}
	return p
}

func (s *ScriptApiImpl) CreateFromAsm(asm string) (script *types.Script, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	}
	hex, err := cfdgo.CfdGoConvertScriptAsmToHex(asm)
	if err != nil {
		return nil, err
	}
	scriptObj, err := types.NewScriptFromHex(hex)
	if err != nil {
		return nil, err
	}
	script = &scriptObj
	return script, nil
}

func (s *ScriptApiImpl) CreateFromAsmStrings(asmStrings []string) (script *types.Script, err error) {
	if len(asmStrings) == 0 {
		return nil, cfdErrors.ErrParameterNil
	}
	asm := strings.Join(asmStrings, " ")
	return s.CreateFromAsm(asm)
}

func (s *ScriptApiImpl) Parse(script *types.Script) (asmStrings []string, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	} else if script == nil {
		return nil, cfdErrors.ErrParameterNil
	}
	asmStrings, err = cfdgo.CfdGoParseScript(script.ToHex())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse script")
	}
	return asmStrings, nil
}

func (s *ScriptApiImpl) ParseMultisig(script *types.Script) (pubkeys []*types.Pubkey, requireSigNum uint32, err error) {
	if s == nil {
		return nil, 0, errors.New(cfdErrors.InternalError.Error())
	} else if script == nil {
		return nil, 0, cfdErrors.ErrParameterNil
	}
	scriptItems, err := cfdgo.CfdGoParseScript(script.ToHex())
	if err != nil {
		return nil, 0, err
	}
	switch {
	case len(scriptItems) < 3:
		return nil, 0, cfdErrors.ErrMultisigScript
	}

	var reqSigNum, totalNum uint32
	pubkeys = make([]*types.Pubkey, 0, len(scriptItems)-2)
	for i, item := range scriptItems {
		switch i {
		case 0, len(scriptItems) - 2:
			numStr := ""
			nums := strings.Split(item, "OP_")
			if len(nums) == 2 {
				numStr = nums[1]
			} else {
				numStr = nums[0]
			}
			if strings.HasPrefix(numStr, "-") {
				return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
			}
			num, err := strconv.ParseUint(numStr, 10, 32)
			if err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
			if i == 0 {
				reqSigNum = uint32(num)
			} else {
				totalNum = uint32(num)
			}
		case len(scriptItems) - 1:
			if item != "OP_CHECKMULTISIG" {
				return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
			}
		default:
			pk := &types.Pubkey{Hex: item}
			err := s.pubkeyApi.Verify(pk)
			if err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
			pubkeys = append(pubkeys, pk)
		}
	}

	switch {
	case reqSigNum == 0:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case reqSigNum < totalNum:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case totalNum != uint32(len(pubkeys)):
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case totalNum > MaxMultisigPubkeyNum:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	}
	if totalNum > MaxP2shMultisigPubkeyNum {
		for _, pubkey := range pubkeys {
			if err := s.pubkeyApi.IsCompressed(pubkey); err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
		}
	}
	return pubkeys, reqSigNum, nil
}

func (s *ScriptApiImpl) CreateMultisig(pubkeys []*types.Pubkey, requireSigNum uint32) (script *types.Script, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	} else if len(pubkeys) == 0 {
		return nil, cfdErrors.ErrParameterNil
	} else if requireSigNum == 0 {
		return nil, cfdErrors.ErrParameterNil
	}
	pks := make([]string, len(pubkeys))
	for i, pk := range pubkeys {
		pks[i] = pk.Hex
	}
	_, scriptHex, _, err := cfdgo.CfdGoCreateMultisigScript(types.Mainnet.ToCfdValue(), types.P2sh.ToCfdValue(), pks, requireSigNum)
	if err != nil {
		return nil, err
	}
	scriptObj, err := types.NewScriptFromHex(scriptHex)
	if err != nil {
		return nil, err
	}
	script = &scriptObj
	return script, nil
}

func (s *ScriptApiImpl) AnalyzeLockingScript(script *types.Script) (
	hashType types.HashType, err error,
) {
	hashType = types.UnknownType
	asmStrings, err := s.Parse(script)
	if err != nil {
		return hashType, err
	}
	for i := range asmStrings {
		asmStrings[i] = strings.ToUpper(asmStrings[i])
	}

	switch len(asmStrings) {
	case 5:
		if s.isP2pkh(asmStrings) {
			return types.P2pkh, nil
		}
	case 3:
		if s.isP2sh(asmStrings) {
			return types.P2sh, nil
		}
	case 2:
		if strings.HasPrefix(asmStrings[1], "OP_") {
			return hashType, errors.Errorf("unknown locking script format")
		}
		witVerStr := asmStrings[0]
		if strings.HasPrefix(asmStrings[0], "OP_") {
			witVerStr = asmStrings[0][3:]
		}
		witnessVersion, err := strconv.Atoi(witVerStr)
		if err != nil {
			return hashType, errors.Wrap(err, "analyze witness version error")
		}
		switch {
		case s.isP2wpkh(witnessVersion, asmStrings[1]):
			return types.P2wpkh, nil
		case s.isP2wsh(witnessVersion, asmStrings[1]):
			return types.P2wsh, nil
		case s.isP2tr(witnessVersion, asmStrings[1]):
			return types.Taproot, nil
		default:
			// do nothing
		}
		if witnessVersion == 0 || witnessVersion == 1 {
			return hashType, errors.Errorf("Invalid witness-%d format", witnessVersion)
		}
	}
	return hashType, errors.Errorf("unknown locking script format")
}

func (s *ScriptApiImpl) IsCheckHashType(
	hashType types.HashType,
	script *types.Script,
) (bool, error) {
	targetHashType, err := s.AnalyzeLockingScript(script)
	if err != nil {
		return false, err
	}
	isEquals := (hashType == targetHashType)
	return isEquals, nil
}

func (s *ScriptApiImpl) isP2pkh(asmStrings []string) bool {
	switch {
	case len(asmStrings) != 5:
	case asmStrings[0] != "OP_DUP":
	case asmStrings[1] != "OP_HASH160":
	case asmStrings[3] != "OP_EQUALVERIFY":
	case asmStrings[4] != "OP_CHECKSIG":
	case strings.HasPrefix(asmStrings[2], "OP_"):
	case len(asmStrings[2]) != 20*2:
	default:
		return true
	}
	return false
}

func (s *ScriptApiImpl) isP2sh(asmStrings []string) bool {
	switch {
	case len(asmStrings) != 3:
	case asmStrings[0] != "OP_HASH160":
	case asmStrings[2] != "OP_EQUAL":
	case strings.HasPrefix(asmStrings[1], "OP_"):
	case len(asmStrings[1]) != 20*2:
	default:
		return true
	}
	return false
}

func (s *ScriptApiImpl) isP2wpkh(witnessVersion int, hash string) bool {
	if (witnessVersion != 0) || strings.HasPrefix(hash, "OP_") || (len(hash) != 20*2) {
		return false
	}
	return true
}

func (s *ScriptApiImpl) isP2wsh(witnessVersion int, hash string) bool {
	if (witnessVersion != 0) || strings.HasPrefix(hash, "OP_") || (len(hash) != 32*2) {
		return false
	}
	return true
}

func (s *ScriptApiImpl) isP2tr(witnessVersion int, hash string) bool {
	if (witnessVersion != 1) || strings.HasPrefix(hash, "OP_") || (len(hash) != 32*2) {
		return false
	}
	return true
}
