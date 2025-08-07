package rbac

type Error struct {
	message string
}

func (e *Error) Error() string {
	return e.message
}

func NewError(message string) *Error {
	return &Error{message}
}

var (
	InsufficientPermissions 	= NewError("Insufficient permissions to perform this action")
	EntityDoesNotHaveSuchAction = NewError("Entity doesn't have such action")
	ActionDeniedByAGP			= NewError("Action has been denied by Action Gate Policy")
)

