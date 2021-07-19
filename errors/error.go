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
	InternalError         CfdError = "CFD Error: Internal error"

	// text
	InvalidConfigErrorMessage string = "Invalid configuration"
)

// Error This function implements the error interface.
func (e CfdError) Error() string {
	return string(e)
}
