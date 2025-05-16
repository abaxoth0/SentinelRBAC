package rbac

import "errors"

type AuthzFunc func(Permissions, Permissions) *Error

var auth AuthzFunc = AuthorizeCRUD

// AuthorizationFunc checks user's permissions.
//
// This function is incapsulated in rbac package, so it can't be called directly,
// instead use "Authorize" function.
//
// AuthorizationFunc can be overridden via this function, to implement custom authorization logic.
// By default it uses the AuthorizeCRUD function.
func SetAuthzFunc(fn AuthzFunc) {
    if fn == nil {
        panic("authorization function can't be nil")
    }

    auth = fn
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD permissions.
//
// It returns an "InsufficientPermissions" error if any of the "required" permissions are not covered by the "permitted" permissions.
func AuthorizeCRUD(required Permissions, permitted Permissions) *Error {
    // To verify that 'permitted' satisfies 'required' need to check
    // if all 1 bits in 'required' are set in 'permitted',
    // For that need to perform a bitwise AND between 'required' and 'permitted',
    // then verify if the result equals 'required'.
    // If (required & permitted) == required, all 1s in required are present in permitted.
    // Proof:
    // r - required, p - permitted, & - bitwise AND (conjunction), c - conjunction result.
    //
    // example #1
    // r:    01101
    //           &
    // p: 11101001
    // -----------
    // c:     1001
    //          ==
    // r:    01101
    // -----------
    //       false (InsufficientPermissions error)
    //
    // example #2
    // r:    10011
    //           &
    // p:   111111
    // -----------
    // c:    10011
    //          ==
    // r:    10011
    // -----------
    //        true (No error)
    if required&permitted != required {
        return InsufficientPermissions
    }

    return nil
}

// Authorize checks if the user has sufficient permissions to perform an action on a resource.
//
// It takes an Action, a Resource, and a list of user's roles.
// It returns an error if any of the required permissions for the action are not covered by the user's roles.
// If the user has sufficient permissions, it returns nil.
func Authorize(act Action, resource *Resource, rolesNames []string) error {
    requiredPermissions := actions[act]

    if requiredPermissions == 0 {
        return errors.New("action \"" + act.String() + "\" wasn't found")
    }

    mergredPermissions := 0

    for _, roleName := range rolesNames {
        mergredPermissions |= resource.RolesPermissions[roleName]
    }

    if err := auth(requiredPermissions, mergredPermissions); err == nil {
        return nil
    }

    return InsufficientPermissions

}

