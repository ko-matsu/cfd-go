package errors

type MultiError struct {
	error
	errs []error
}

// NewMultiError returns MultiError object.
func NewMultiError(err error, errors ...error) *MultiError {
	multiErr := MultiError{
		error: err,
		errs:  errors,
	}
	return &multiErr
}

func (e MultiError) Exist() bool {
	return len(e.errs) > 0
}

func (e MultiError) GetErrors() []error {
	if len(e.errs) == 0 {
		return []error{}
	}
	result := make([]error, 0, len(e.errs))
	result = append(result, e.errs...)
	return result
}

func (e *MultiError) Add(err error) {
	if err == nil {
		return
	}
	if e.errs == nil {
		e.errs = make([]error, 1)
		e.errs[0] = err
	} else {
		e.errs = append(e.errs, err)
	}
}

func (e *MultiError) Append(errs *MultiError) {
	if errs == nil || len(errs.errs) == 0 {
		return
	}
	if e.errs == nil {
		e.errs = make([]error, 0, len(errs.errs))
	}
	e.errs = append(e.errs, errs.errs...)
}

func (e *MultiError) SetError(err error) {
	if err != nil {
		e.error = err
	}
}

// Append returns multiple errors.
func Append(err *MultiError, appendErrors ...error) *MultiError {
	if len(appendErrors) == 0 {
		return err
	}

	errObj := err
	if err == nil {
		errObj = &MultiError{}
	}

	for _, appendErr := range appendErrors {
		if appendErr == nil {
			// do nothing
		} else if multiErr, ok := appendErr.(*MultiError); ok {
			errObj.Append(multiErr)
		} else {
			errObj.Add(appendErr)
		}
	}
	return errObj
}

// GetErrors returns error array.
func GetErrors(err error) []error {
	if err == nil {
		return []error{}
	} else if multiErr, ok := err.(*MultiError); ok {
		if multiErr == nil {
			return []error{}
		}
		return multiErr.GetErrors()
	} else {
		return []error{err}
	}
}
