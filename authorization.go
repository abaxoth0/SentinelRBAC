package rbac

type AuthzFunc func(Permissions, Permissions) *Error

var authorize AuthzFunc = AuthorizeCRUD

// AuthorizationFunc checks user's permissions.
//
// This function is incapsulated in rbac package, so it can't be called directly,
// instead use "Authorize" method of any existing resource.
//
// AuthorizationFunc can be overridden via this function, to implement custom authorization logic.
// By default it uses the AuthorizeCRUD function.
func SetAuthzFunc(fn AuthzFunc) {
    if fn == nil {
        panic("authorization function can't be nil")
    }

    authorize = fn
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

