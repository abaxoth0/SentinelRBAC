package rbac

// Bitmask
type Permissions = uint16

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

