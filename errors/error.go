package errors

type CfdError string

const (
	// error
	ErrNetworkConfig      CfdError = "CFD Error: Invalid network configuration"
	InterfaceSettingError CfdError = "CFD Error: Invalid interfaces"
	ElementsNetworkError  CfdError = "CFD Error: Network configuration is not elements"
	BitcoinNetworkError   CfdError = "CFD Error: Network configuration is not bitcoin"
	ParameterNilError     CfdError = "CFD Error: Parameter is nil"
	UnmatchNetworkError   CfdError = "CFD Error: network type is unmatching"
	DuplicateOptionError  CfdError = "CFD Error: duplicate configuration option"
	InternalError         CfdError = "CFD Error: Internal error"

	// text
	InterfaceSettingErrorMessage string = "Failed to set interfaces"
	InvalidConfigErrorMessage    string = "Invalid configuration"
	CreateDefaultApiErrorMessage string = "create default api error"
)

// Error This function implements the error interface.
func (e CfdError) Error() string {
	return string(e)
}
