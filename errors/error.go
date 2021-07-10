package errors

type CfdError string

const (
	// error
	InterfaceSettingError CfdError = "CFD Error: Invalid interfaces"
	NetworkConfigError    CfdError = "CFD Error: Invalid network configuration"
	ElementsNetworkError  CfdError = "CFD Error: Network configuration is not elements"
	BitcoinNetworkError   CfdError = "CFD Error: Network configuration is not bitcoin"
	ParameterNilError     CfdError = "CFD Error: Parameter is nil"

	// text
	InterfaceSettingErrorMessage string = "Failed to set interfaces"
	InvalidConfigErrorMessage    string = "Invalid configuration"
	CreateDefaultApiErrorMessage string = "create default api error"
	InternalErrorMessage         string = "CFD Error: Internal error"
)

// Error This function implements the error interface.
func (e CfdError) Error() string {
	return string(e)
}