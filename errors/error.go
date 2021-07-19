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

// Error returns the error string.
func (e CfdError) Error() string {
	return string(e)
}

// HasInitializeError has a InitializeError object.
type HasInitializeError struct {
	InitializeError error
}

// SetError returns HasInitializeError pointer.
func (e *HasInitializeError) SetError(err error) *HasInitializeError {
	if err == nil {
		return e
	}
	var multiError *MultiError
	if e == nil {
		e = &HasInitializeError{}
		multiError = NewMultiError(CfdError("CFD Error: initialize error"))
	} else {
		var ok bool
		if multiError, ok = e.InitializeError.(*MultiError); !ok {
			multiError = NewMultiError(CfdError("CFD Error: initialize error"))
		}
	}
	multiError.Add(err)
	e.InitializeError = multiError
	return e
}

// GetError returns error interface.
func (e *HasInitializeError) GetError() error {
	if e == nil {
		return nil
	}
	return e.InitializeError
}

// HasError returns error exist flag.
func (e *HasInitializeError) HasError() bool {
	if e == nil {
		return false
	}
	return e.InitializeError != nil
}
