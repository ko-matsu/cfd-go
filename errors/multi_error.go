package errors

type MultiError struct {
	errs []error
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
	if e.errs == nil {
		e.errs = make([]error, 1)
		e.errs[0] = err
	} else {
		e.errs = append(e.errs, err)
	}
}

func (e *MultiError) Append(errs MultiError) {
	errors := errs.GetErrors()
	if len(errors) == 0 {
		return
	} else if e.errs == nil {
		e.errs = make([]error, 0, len(errors))
	}
	e.errs = append(e.errs, errors...)
}
