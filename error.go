package rbac

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

func NewError(message string) *Error {
	return &Error{message}
}

var InsufficientPermissions *Error = NewError("Insufficient permissions to perform this action")
