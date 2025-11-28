package rbac

import (
	"testing"
)

func TestError(t *testing.T) {
	// Test error interface implementation
	var errorInterface error = ErrInsufficientPermissions
	if errorInterface == nil {
		t.Error("Error should implement error interface")
	}

	// Test predefined errors
	if ErrInsufficientPermissions.Error() != "insufficient permissions to perform this action" {
		t.Error("ErrInsufficientPermissions message incorrect")
	}

	if ErrEntityDoesNotHaveSuchAction.Error() != "entity doesn't have such action" {
		t.Error("ErrEntityDoesNotHaveSuchAction message incorrect")
	}

	if ErrActionDeniedByAGP.Error() != "action has been denied by action gate policy" {
		t.Error("ErrActionDeniedByAGP message incorrect")
	}

	// Test legacy support
	if ErrInsufficientPermissions.Error() != "insufficient permissions to perform this action" {
		t.Error("Legacy InsufficientPermissions message incorrect")
	}

	if ErrEntityDoesNotHaveSuchAction.Error() != "entity doesn't have such action" {
		t.Error("Legacy EntityDoesNotHaveSuchAction message incorrect")
	}

	if ErrActionDeniedByAGP.Error() != "action has been denied by action gate policy" {
		t.Error("Legacy ActionDeniedByAGP message incorrect")
	}
}
