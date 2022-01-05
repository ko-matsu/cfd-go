package types

// PakEntry ...
type PakEntry struct {
	ByteData
}

// NewPakEntry ...
func NewPakEntry(data ByteData) *PakEntry {
	bytes := data.ToSlice()
	if len(bytes) != 66 {
		return nil
	}
	pakEntry := PakEntry{NewByteData(bytes)}
	return &pakEntry
}

// Valid ...
func (p *PakEntry) Valid() bool {
	return p != nil && len(p.hex) == 132
}

// String ...
func (p *PakEntry) String() string {
	if !p.Valid() {
		return ""
	}
	pakEntryStr := p.ToHex()
	return "pak=" + pakEntryStr[0:66] + ":" + pakEntryStr[66:132]
}
