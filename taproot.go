package cfdgo

import (
	"strings"
	"unsafe"
)

// internalCreateScriptTreeHandle This function is create cfd handle and script tree handle.
func internalCreateScriptTreeHandle() (handle uintptr, treeHandle uintptr, err error) {
	handle, err = CfdGoCreateHandle()
	if err != nil {
		return uintptr(0), uintptr(0), err
	}

	ret := CfdInitializeTaprootScriptTree(handle, &treeHandle)
	err = convertCfdError(ret, handle)
	if err != nil {
		CfdGoFreeHandle(handle)
		return uintptr(0), uintptr(0), err
	}
	return handle, treeHandle, err
}

// TapBranch This struct use for the taproot script tree branch.
type TapBranch struct {
	// Branch Hash
	Hash ByteData
	// TapScript
	TapScript Script
	// tree string
	treeStr string
	// target node string
	targetNodeStr string
}

// internalLoadTapBranchFromStringByNodes This function has load branch by nodes.
func internalLoadTapBranchFromStringByNodes(handle, treeHandle uintptr, treeStr string, tapscript *Script, targetNodes string) error {
	script := ""
	node := ""
	if tapscript != nil {
		script = tapscript.ToHex()
		node = targetNodes
	}
	leafVersion := uint8(0xc0)
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	ret := CfdSetScriptTreeFromString(handle, treeHandle, treeStr, script, leafVersionPtr, node)
	return convertCfdError(ret, handle)
}

// internalGetTapBranchData This function return a TapBranch.
func internalGetTapBranchData(handle, treeHandle uintptr, treeStr string, tapscript *Script, targetNodes string) (branch *TapBranch, err error) {
	script := ""
	node := ""
	if tapscript != nil {
		script = tapscript.ToHex()
		node = targetNodes
	}

	count := uint32(0)
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTapBranchCount(handle, treeHandle, countPtr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	targetNodeStr := node
	var hash string
	var tempScript string
	leafVersion := uint8(0xc0)
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	depth := uint8(0)
	depthPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&depth)))
	if count == uint32(0) { // single leaf
		ret = CfdGetBaseTapLeaf(handle, treeHandle, leafVersionPtr, &tempScript, &hash)
	} else { // top branch
		index := uint8(0)
		indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
		ret = CfdGetTapBranchData(handle, treeHandle, indexPtr, true, &hash, leafVersionPtr, &tempScript, depthPtr)
	}
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}

	if len(script) != 0 && len(node) == 0 {
		for idx := uint8(0); idx < uint8(count); idx++ {
			var branchHash string
			idxPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&idx)))
			ret = CfdGetTapBranchData(handle, treeHandle, idxPtr, false, &branchHash, leafVersionPtr, &tempScript, depthPtr)
			if err = convertCfdError(ret, handle); err != nil {
				return nil, err
			}
			targetNodeStr += branchHash
		}
	}

	branch = &TapBranch{
		Hash:          ByteData{hex: hash},
		TapScript:     Script{hex: script},
		treeStr:       treeStr,
		targetNodeStr: targetNodeStr,
	}
	return branch, nil
}

// NewTapBranchFromHash This function return a TapBranch.
func NewTapBranchFromHash(hash *ByteData) (*TapBranch, error) {
	if hash == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	if len(hash.hex) != 64 {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	emptyScript := Script{hex: ""}
	treeStr := hash.ToHex()
	return &TapBranch{
		Hash:          *hash,
		TapScript:     emptyScript,
		treeStr:       treeStr,
		targetNodeStr: "",
	}, nil
}

// NewTapBranchFromTapScript This function return a TapBranch from tapscript.
func NewTapBranchFromTapScript(tapscript *Script) (*TapBranch, error) {
	if tapscript == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	leafVersion := uint8(0xc0)
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	ret := CfdSetInitialTapLeaf(handle, treeHandle, tapscript.ToHex(), leafVersionPtr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	var treeStr string
	ret = CfdGetTaprootScriptTreeSrting(handle, treeHandle, &treeStr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, treeStr, tapscript, "")
	return branch, err
}

// NewTapBranchFromString This function return a TapBranch from tree string.
func NewTapBranchFromString(treeStr string, tapscript *Script) (*TapBranch, error) {
	branch, err := NewTapBranchFromStringByNodes(treeStr, tapscript, []string{})
	return branch, err
}

// NewTapBranchFromStringByNodes This function return a TapBranch from tree string and nodes.
func NewTapBranchFromStringByNodes(treeStr string, tapscript *Script, nodes []string) (*TapBranch, error) {
	targetNodes := ""
	if tapscript != nil && len(nodes) > 0 {
		targetNodes = strings.Join(nodes, "")
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, treeStr, tapscript, targetNodes)
	if err != nil {
		return nil, err
	}

	return internalGetTapBranchData(handle, treeHandle, treeStr, tapscript, targetNodes)
}

// NewTapBranchFromControlBlock This function return a TapBranch from control block.
func NewTapBranchFromControlBlock(controlBlock *ByteData, tapscript *Script) (branch *TapBranch, internalPubkey *ByteData, err error) {
	if controlBlock == nil || tapscript == nil {
		return nil, nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}

	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	internalPubkeyStr := ""
	ret := CfdSetTapScriptByWitnessStack(handle, treeHandle, controlBlock.ToHex(), tapscript.ToHex(), &internalPubkeyStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, err
	}

	var tempScript string
	var hash string
	leafVersion := uint8(0xc0)
	leafVersionPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&leafVersion)))
	index := uint8(0)
	indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
	depth := uint8(0)
	depthPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&depth)))
	ret = CfdGetTapBranchData(handle, treeHandle, indexPtr, true, &hash, leafVersionPtr, &tempScript, depthPtr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, err
	}

	var treeStr string
	ret = CfdGetTaprootScriptTreeSrting(handle, treeHandle, &treeStr)
	err = convertCfdError(ret, handle)
	if err != nil {
		return nil, nil, err
	}

	branch, err = internalGetTapBranchData(handle, treeHandle, treeStr, tapscript, "")
	if err != nil {
		return nil, nil, err
	}

	internalPubkey = &ByteData{hex: internalPubkeyStr}
	return branch, internalPubkey, nil
}

// GetTreeString This function return a tapbranch tree string.
func (obj *TapBranch) GetTreeString() string {
	return obj.treeStr
}

// AddBranchByTapScript This function is adding a tapscript.
func (obj *TapBranch) AddBranchByTapScript(tapscript *Script) error {
	if tapscript == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	treeStr := "tl(" + tapscript.ToHex() + ")"
	return obj.AddBranchByString(treeStr)
}

// AddBranchByHash This function is adding a tapbranch hash.
func (obj *TapBranch) AddBranchByHash(hash *ByteData) error {
	if hash == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	return obj.AddBranchByString(hash.hex)
}

// AddBranchByBranch This function is adding a tapbranch.
func (obj *TapBranch) AddBranchByBranch(branch *TapBranch) error {
	if branch == nil {
		return convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	return obj.AddBranchByString(branch.treeStr)
}

// AddBranchByString This function return a tapbranch string.
func (obj *TapBranch) AddBranchByString(treeStr string) error {
	addBranch, err := NewTapBranchFromString(treeStr, nil)
	if err != nil {
		return err
	}

	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr)
	if err != nil {
		return err
	}

	ret := CfdAddTapBranchByScriptTreeString(handle, treeHandle, treeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	var newTreeStr string
	ret = CfdGetTaprootScriptTreeSrting(handle, treeHandle, &newTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return err
	}

	branch, err := internalGetTapBranchData(handle, treeHandle, newTreeStr, &obj.TapScript, obj.targetNodeStr)
	if err == nil {
		obj.Hash = branch.Hash
		obj.treeStr = newTreeStr
		obj.targetNodeStr = obj.targetNodeStr + addBranch.Hash.ToHex()
	}
	return err
}

// GetMaxBranchCount This function return a branch count.
func (obj *TapBranch) GetMaxBranchCount() (count uint32, err error) {
	count = uint32(0)
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr)
	if err != nil {
		return
	}

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetTapBranchCount(handle, treeHandle, countPtr)
	err = convertCfdError(ret, handle)
	return
}

// GetBranch This function return a tapbranch.
func (obj *TapBranch) GetBranch(index uint8) (branch *TapBranch, err error) {
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr)
	if err != nil {
		return
	}

	var branchHandle uintptr
	var hash string
	indexPtr := SwigcptrUint8_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTapBranchHandle(handle, treeHandle, indexPtr, &hash, &branchHandle)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}
	defer CfdGoFreeScriptTreeHandle(handle, branchHandle)

	var branchTreeStr string
	ret = CfdGetTaprootScriptTreeSrting(handle, branchHandle, &branchTreeStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}

	return internalGetTapBranchData(handle, branchHandle, branchTreeStr, nil, "")
}

// GetControlNodeList This function return control node list.
func (obj *TapBranch) GetControlNodeList() (nodeList []string, err error) {
	nodeList = []string{}
	if obj.TapScript.IsEmpty() {
		return nodeList, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
	}
	if len(obj.targetNodeStr) == 0 {
		return nodeList, nil
	}
	if (len(obj.targetNodeStr) % 64) != 0 {
		return nodeList, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
	}
	offset := 0
	endOffset := 0
	count := len(obj.targetNodeStr) / 64
	nodeList = make([]string, count)
	for index := 0; index < count; index++ {
		offset = 64 * index
		endOffset = offset + 64
		nodeList[index] = obj.targetNodeStr[offset:endOffset]
	}
	return nodeList, nil
}

// GetTweakedPubkey This function return a tweaked pubkey by tapscript tree.
func (obj *TapBranch) GetTweakedPubkey(internalPubkey *ByteData) (pubkey *ByteData, tapLeafHash *ByteData, controlBlock *ByteData, err error) {
	if internalPubkey == nil {
		return nil, nil, nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	if obj.TapScript.IsEmpty() {
		return nil, nil, nil, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, nil, nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr)
	if err != nil {
		return nil, nil, nil, err
	}

	var branchHash string
	var tapLeafHashStr string
	var controlBlockStr string
	ret := CfdGetTaprootScriptTreeHash(handle, treeHandle, internalPubkey.ToHex(), &branchHash, &tapLeafHashStr, &controlBlockStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, nil, nil, err
	}

	return &ByteData{hex: branchHash}, &ByteData{hex: tapLeafHashStr}, &ByteData{hex: controlBlockStr}, nil
}

// GetTweakedPrivkey This function return a tweaked privkey by tapscript tree.
func (obj *TapBranch) GetTweakedPrivkey(internalPrivkey *ByteData) (privkey *ByteData, err error) {
	if internalPrivkey == nil {
		return nil, convertCfdError(int(KCfdIllegalArgumentError), uintptr(0))
	}
	if obj.TapScript.IsEmpty() {
		return nil, convertCfdError(int(KCfdIllegalStateError), uintptr(0))
	}
	handle, treeHandle, err := internalCreateScriptTreeHandle()
	if err != nil {
		return nil, err
	}
	defer CfdGoFreeHandle(handle)
	defer CfdGoFreeScriptTreeHandle(handle, treeHandle)

	err = internalLoadTapBranchFromStringByNodes(handle, treeHandle, obj.treeStr, &obj.TapScript, obj.targetNodeStr)
	if err != nil {
		return nil, err
	}

	var privkeyStr string
	ret := CfdGetTaprootTweakedPrivkey(handle, treeHandle, internalPrivkey.ToHex(), &privkeyStr)
	if err = convertCfdError(ret, handle); err != nil {
		return nil, err
	}

	return &ByteData{hex: privkeyStr}, nil
}
