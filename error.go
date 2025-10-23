package rbac

import "errors"

var (
	ErrInsufficientPermissions     = errors.New("insufficient permissions to perform this action")
	ErrEntityDoesNotHaveSuchAction = errors.New("entity doesn't have such action")
	ErrActionDeniedByAGP           = errors.New("action has been denied by action gate policy")
)
