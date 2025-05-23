## Role-Based Access Control (RBAC)

SentinelRBAC is library for authorization, it helps you as a developer to define users permissions in your application.

### ROLES

Each role consist of 2 parts: name and default permissions for this role.

There are no built-in roles, all roles must be defined by developer.

### PERMISSIONS

Permissions are represented via bitmask, so they are very fast to work with.

There are 8 permissions:

-   Create

-   Self Create

-   Read

-   Self Read

-   Update

-   Self Update

-   Delete

-   Self Delete

I assume that there are no need to describe what each one of them permit to do.

### Entity

Entity is a subject wich will be authorized to perform actions on a specific resources.

In most cases you will have only 1 entity in your application - user.

### Action

Action is just a type definition based on string. It represents name of this action. Each action is bound to specific entity.

Action can be create via `.NewAction(<name>, <required permissions>)` method of some entity.

### Resource

Resource is an object on wich action is supposed to be performed. Resource contains allowed permissions for each role,
so it provide more flexiblility in permissions configurations.

### Authorization

To authorize some action you need 4 things: roles, entity, action itself and resource.

Example:

```go
package main

import (
    "fmt"

    rbac "github.com/StepanAnanin/SentinelRBAC"
)

func main() {
    roles := []rbac.Role{
        //    10101
        rbac.NewRole("admin", rbac.CreatePermission|rbac.ReadPermission|rbac.UpdatePermission),
        //   100101
        rbac.NewRole("moderator", rbac.CreatePermission|rbac.ReadPermission|rbac.SelfUpdatePermission),
        // 10101000
        rbac.NewRole("user", rbac.SelfReadPermission|rbac.SelfUpdatePermission|rbac.SelfDeletePermission),
    }

    userRoles1 := roles[:1]
    userRoles2 := roles[1:]

    user := rbac.NewEntity("user")

    // This is required permissions for this action
    act, err := user.NewAction("delete", rbac.DeletePermission)
    if err != nil {
        panic(err)
    }

    // Resources contains roles (and roles contains allowed permissions)
    cache := rbac.NewResource("cache", roles)

    // Inside of resource you can change role permissions as it requires
    // It won't affect original roles, cuz each resource uses a copy of roles' permissions.
    cache.RolesPermissions["admin"] = rbac.DeletePermission

    e := cache.Authorize(act, rbac.GetRolesNames(userRoles1))

    // Error: <nil>
    fmt.Println(e)

    e = cache.Authorize(act, rbac.GetRolesNames(userRoles2))

    // Error: Insufficient permissions to perform this action
    fmt.Println(e)

    // (0 index is "admin" role)
    // 10101, even if previously it was set to 1000000 (rbac.DeletePermission),
    // this change doesn't affect original or other resource's roles permissions,
    fmt.Println(strconv.FormatInt(int64(roles[0].Permissions), 2))
}
```

## Schema

`Schema` designed to help you organize roles in convenient human-readble form.

You can also select several roles as default roles, all new users must have this roles.

`Schema` should be defined in it's own file in JSON format. It can be loaded via **LoadSchema(path string) (Schema, error)**.

### Schema configuration example

```json
{
    "id": "schema-id", (optional)
    "name": "my-schema", (optional)
    "default-roles": [ (optional)
        "user"
    ],
    "roles": [
        {
            "name": "user",
            "permissions": {
                "read": false,
                "self-read": true,
                "create": false,
                "self-create": false,
                "update": false,
                "self-update": true,
                "delete": false,
                "self-delete": true
            }
        },
        {
            "name": "moderator",
            "permissions": {
                "read": true,
                "self-read": true,
                "create": true,
                "self-create": true,
                "update": true,
                "self-update": true,
                "delete": true,
                "self-delete": true
            }
        },
        {
            "name": "admin",
            "permissions": {
                "read": true,
                "self-read": true,
                "create": true,
                "self-create": true,
                "update": true,
                "self-update": true,
                "delete": true,
                "self-delete": true
            }
        }
    ]
}
```

## Host

`Host` originaly designed for applications with microservice architectures.

`Host` is based on `Schema`, using it you can define multiple schemas.
Like each schema, `Host` can have roles and global roles, in this case they considered as global.
All schemas in `Host` must have all its global roles, but permissions for this roles may differ in each schema.

> [!WARNING]
> Schema specific roles permissions will overwrite global roles permissions!

`Host` can be initialized by one of the following methods:

-   **LoadHost(path string) (Host, error)** - Open and reads configuration file (JSON) at the specified path and after parsing returns it. This method also validates permissions and merges permissions of the global roles with permissions of the service specific (Schema) roles. This method is recommended way of `Host` initialization. (And currently the only one)

### Host example

```json
{
    "default-roles": [
        "user"
    ],
    "roles": [
        {
            "name": "user",
            "permissions": {
                "read": false,
                "self-read": true,
                "create": false,
                "self-create": false,
                "update": false,
                "self-update": true,
                "delete": false,
                "self-delete": true
            }
        },
        {
            "name": "moderator",
            "permissions": {
                "read": true,
                "self-read": true,
                "create": true,
                "self-create": true,
                "update": true,
                "self-update": true,
                "delete": true,
                "self-delete": true
            }
        },
        {
            "name": "admin",
            "permissions": {
                "read": true,
                "self-read": true,
                "create": true,
                "self-create": true,
                "update": true,
                "self-update": true,
                "delete": true,
                "self-delete": true
            }
        }
    ],
    "schemas": [
        {
            "id": "5b87cfb3-4d13-4d1d-ab3d-44d5d0c17b8a",
            "name": "post-service",
            "default-roles": [
                "moderator",
            [,
            "roles": [
                {
                    "name": "user",
                    "permissions": {
                        "read": false,
                        "self-read": true,
                        "create": false,
                        "self-create": false,
                        "update": false,
                        "self-update": false,
                        "delete": false,
                        "self-delete": false
                    }
                }
            ]
        }
    ]
}
```
