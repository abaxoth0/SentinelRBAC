## Role-Based Access Control (RBAC)

SentinelRBAC is library for authorization, it helps you as a developer to define users permissions in your application.

All roles and services are defined into variable named `Schema`, it's `nil` by default and can be initialized by one of the following methods:

-   **LoadSchema(path string)** - Open and reads configuration file at the specified path, then this method parse it and assign to `Schema` variable. This method also validates `Schema` permissions and merges default roles with service specific roles, so consider this method as recommended way of `Schema` initialization.

-   **DefineSchema(DefaultRoles []Role, Services []Service)** - Initializing new variable and assign `Schema` to it.

### ROLES

Roles can be specified by default or services can have their own roles.

> Service specific roles will overwrite default roles.

### PERMISSIONS

Permissions can be specified by using special tags. Now there are 10 permission tags:

-   C (Create) - can create any entities

-   SC (Self Create) - can create entities, which will belong to this user

-   R (Read) - can read any entity

-   SR (Self Read) - can read entities, that was created by this user (also can read himself)

-   U (Update) - can modify any entity

-   SU (Self Update) - can modify entities, that was created by this user (also can update himself)

-   D (Delete) - can delete any entity

-   SD (Delete) - can delete entities, that was created by this user

-   M (Moderator) - can do moderator-specific actions and have C, R, U, D permissions, even if they are not specified.

-   A (Admin) - full access

### CONFIG EXAMPLE

```json
{
    "default-roles": [
        {
            "name": "unconfirmed_user",
            "permissions": ["SD"]
        },
        {
            "name": "restricted_user",
            "permissions": ["SR"]
        },
        {
            "name": "user",
            "permissions": ["SR", "SU", "SD"]
        },
        {
            "name": "support",
            "permissions": ["R", "SU"]
        },
        {
            "name": "moderator",
            "permissions": ["C", "R", "U", "D", "M"]
        },
        {
            "name": "admin",
            "permissions": ["C", "R", "U", "D", "A"]
        }
    ],
    "services": [
        {
            "id": "5b87cfb3-4d13-4d1d-ab3d-44d5d0c17b8a",
            "name": "some-service",
            "roles": [
                {
                    "name": "user",
                    "permissions": ["R", "SU", "SD"]
                }
            ]
        }
    ]
}
```
