package rbac

// bitmask
type Permissions = int

const (
    CreatePermission Permissions = 1 << iota
    SelfCreatePermission
    ReadPermission
    SelfReadPermission
    UpdatePermission
    SelfUpdatePermission
    DeletePermission
    SelfDeletePermission
)

