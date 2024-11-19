## Role-Based Access Control (RBAC)

SentinelRBAC is library for authorization, it helps you as a developer to define users permissions in your application.

All roles and services are defined into variable named `Schema`, it's `nil` by default and can be initialized by one of the following methods:

-   **LoadSchema(path string)** - Open and reads configuration file (JSON) at the specified path, then this method parse it and assign to `Schema` variable. This method also validates `Schema` permissions and merges default roles with service specific roles, so consider this method as recommended way of `Schema` initialization.

-   **NewSchemaBuilder** - Creates builder for schema. When all desired fields will be set use method `Build`, which will assign schema that was built to `Schema` variable.

### ROLES

Roles can be specified by default or services can have their own roles.

> [!NOTE]
> Service specific roles will overwrite default roles!

You can also select one of default roles as origin role, all new users must have this role in your application.

### PERMISSIONS

There are 11 permissions:

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

-   Service - can do service-specific actions, this permission can also be used to determine whether a user is a service.

-   Moderator - pretty same as Service, but also have C, R, U, D permissions, even if they are not specified.

-   Admin - full access.

### CONFIG EXAMPLE

```json
{
    "default-roles": [
        {
            "name": "unconfirmed_user",
            "permissions": ["SELF-DELETE"]
        },
        {
            "name": "restricted_user",
            "permissions": ["SELF-READ"]
        },
        {
            "name": "user",
            "permissions": ["SELF-READ", "SELF-UPDATE", "SELF-DELETE"]
        },
        {
            "name": "support",
            "permissions": ["READ", "SELF-UPDATE"]
        },
        {
            "name": "moderator",
            "permissions": ["MODERATOR"]
        },
        {
            "name": "admin",
            "permissions": ["ADMIN"]
        }
    ],
    "origing-role": "unconfirmed_user",
    "services": [
        {
            "id": "5b87cfb3-4d13-4d1d-ab3d-44d5d0c17b8a",
            "name": "some-service",
            "roles": [
                {
                    "name": "user",
                    "permissions": ["READ", "SELF-UPDATE", "SELF-DELETE"]
                }
            ]
        }
    ]
}
```
