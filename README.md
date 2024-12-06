## Role-Based Access Control (RBAC)

SentinelRBAC is library for authorization, it helps you as a developer to define users permissions in your application.

All roles and services are defined into variable named `Schema`, it's `nil` by default and can be initialized by one of the following methods:

-   **LoadSchema(path string)** - Open and reads configuration file (JSON) at the specified path, then this method parse it and assign to `Schema` variable. This method also validates `Schema` permissions and merges default roles with service specific roles, so consider this method as recommended way of `Schema` initialization.

### ROLES

Roles can be specified by default or services can have their own roles.

> [!NOTE]
> Service specific roles will overwrite default roles!

You can also select one of default roles as origin role, all new users must have this role in your application.

### PERMISSIONS

There are 8 permissions:

> [!NOTE]
> The user himself is also an entity.

-   Create - can create any entities.

-   Self Create - can create entities, which will be related to this user.

-   Read - can read any entity.

-   Self Read - can read entities, related to this user.

-   Update - can modify any entity.

-   Self Update - can modify entities, related to this user.

-   Delete - can delete any entity.

-   Delete - can delete entities, related to this user.

### CONFIG EXAMPLE

```json
{
    "default-roles": [
        {
            "name": "unconfirmed_user",
            "permissions": {
                "read": false,
                "self-read": false,
                "create": false,
                "self-create": false,
                "update": false,
                "self-update": false,
                "delete": false,
                "self-delete": true
            }
        },
        {
            "name": "restricted_user",
            "permissions": {
                "read": false,
                "self-read": true,
                "create": false,
                "self-create": false,
                "update": false,
                "self-update": false,
                "delete": false,
                "self-delete": true
            }
        },
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
            "name": "support",
            "permissions": {
                "read": true,
                "self-read": false,
                "create": false,
                "self-create": false,
                "update": false,
                "self-update": true,
                "delete": false,
                "self-delete": false
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
    "origing-role": "unconfirmed_user",
    "schemas": [
        {
            "id": "5b87cfb3-4d13-4d1d-ab3d-44d5d0c17b8a",
            "name": "post-service",
            "roles": [
                {
                    "name": "unconfirmed_user",
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
