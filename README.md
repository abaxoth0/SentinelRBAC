## About

SentinelRBAC is a lightweight role-based access control (RBAC) authorization engine.

## How does it work?

First of all, you need to determine `who` is trying to do `what` and `with whom`. Let's take it step by step:

### Who? - Entity

Entity is a subject which will be authorized to perform actions on specific resources.

In most cases you will have only 1 entity in your application - user.

### What? - Action

Action just represents name of this action (under the hood is just a type definition based on string). Each action is bound to specific entity.

Action can be created via `.NewAction(<name>, <required permissions>)` method of some entity.

### With whom? - Resource

Resource is a thing on which action is supposed to be performed.

### Context

Pretty simple, isn't it? All these 3 things combined together represent an `Authorization Context`, since they are used to show what actually happens during authorization. But this still won't be enough, because we also need to know what this specific entity is allowed to do, in other words - it's `Permissions`.

### PERMISSIONS

Permissions are represented via bitmask, so they are very fast to work with. There are 8 permissions:

-   Create

-   Self Create

-   Read

-   Self Read

-   Update

-   Self Update

-   Delete

-   Self Delete

I assume that there is no need to describe what each one of them should permit to do.

But how to store all these permissions? Of course we could just leave it as a bitmask (which is just a number), but it will be really hard to maintain. So we need a more convenient way to represent all these permissions and for that we will use `Roles`.

### ROLES

Each role consists of 2 parts: the name and permissions for this role. You can think of them as a named set of permissions.

### Authorization

Now we have all that is required for authorization: `Authorization Context` (`Entity` + `Action` + `Resource`) and `Roles` (which contains `Permissions`). To do that you need to use `Authorize()` function.

Example:

```go
package main

import (
    "fmt"

    rbac "github.com/abaxoth0/SentinelRBAC"
)

var (
    adminRole 	  = rbac.NewRole("admin", rbac.CreatePermission|rbac.ReadPermission|rbac.UpdatePermission|rbac.DeletePermission)
    moderatorRole = rbac.NewRole("moderator", rbac.CreatePermission|rbac.ReadPermission|rbac.SelfUpdatePermission)
    userRole 	  = rbac.NewRole("user", rbac.SelfReadPermission|rbac.SelfUpdatePermission|rbac.SelfDeletePermission)
)

func main() {
    roles1 := []rbac.Role{userRole, adminRole}
    roles2 := []rbac.Role{userRole, moderatorRole}

    // This is the one who will perform the actions.
    user := rbac.NewEntity("user")

    // This is an action and the necessary permissions for it.
    // Note that this action is belong to the specific entity.
    act, err := user.NewAction("delete", rbac.DeletePermission)
    if err != nil {
        panic(err)
    }

    // [{user 168} {admin 85}]
    fmt.Println(roles1)
    // [{user 168} {moderator 37}]
    fmt.Println(roles2)

    // This is the one the actions will be performed on.
    cache := rbac.NewResource("cache")

    // Context of authorization
    ctx := rbac.NewAuthorizationContext(&user, act, cache)

    // Authorize context with the one set of roles...
    e := rbac.Authorize(&ctx, roles1, nil)
    // Error: <nil>
    fmt.Println(e)
    // ... and with another one
    e = rbac.Authorize(&ctx, roles2, nil)
    // Error: Insufficient permissions to perform this action
    fmt.Println(e)
}
```

## Development

### Running Tests
```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Run tests with coverage
make test-coverage

# Generate detailed coverage report
make coverage
```

### Code Quality
```bash
# Run linters
make lint

# Build the project
make build

# Clean build artifacts
make clean
```

### CI/CD
This project uses GitHub Actions for continuous integration:
- **Tests**: Run on every push and pull request
- **Linting**: Code formatting and quality checks
- **Build**: Ensures the project builds successfully
- **Coverage**: Test coverage reporting

## Action Gate Policy (AGP)

As you can see `Authorize()` function actually has 3 arguments, we already know about first two - context and roles, but what about the last one?
This is used for the thing called `Action Gate Policy`. It is used to make authorization more flexible by introducing special rules for certain authorization cases.

This policy can be created via `NewActionGatePolicy()` function, but you also need to add rules into this policy to make it work.

To add rule into the policy first of all you need to create this rule, you can use `NewActionGateRule()` function for that, either just create it manually using `ActionGateRule` type. Rule itself is consist of context, effect of rule (`ActionGateEffect`) and roles, to which this rule must be applied.

Once created, rule can be added to the policy via `AddRule()` method.

> [!WARNING]
> Only valid rules can be added into the policy. Also rule for this context must not already exist in the policy.
> A rule considered valid if it specifies authorization context (Entity, Action, Resource), effect and roles.
>
> Also ensure that specified entity, action and resource exists in your schema if you creating AGP manually.
> (if you are using configuration file all this will be automatically validated)

There are all existing effects:

| Name    | Variable name             | Effect                                                                                     |
| ------- | ------------------------- | ------------------------------------------------------------------------------------------ |
| Deny    | `DenyActionGateEffect`    | Deny action regardless of permissions                                                      |
| Require | `RequireActionGateEffect` | Require specific role(-s). Without this role(-s) all authorization attempts will be denied |
| Allow   | `AllowActionGateEffect`   | Immediately authorize regardless of permissions                                            |

> [!CAUTION]
> Although you can create your own effects, since `ActionGateEffect` is public type, **you must not do this at any circumstances**.
> If you will try to do that anyway - `AddRule()` method will return error if it will found effect which differs from effects specified in the table above.
>
> Why? - Cuz all effects are handled internaly and there are no way to add your own custom handlers for them.

Reworked authorization example with AGP:

```go
package main

import (
    "fmt"

    rbac "github.com/abaxoth0/SentinelRBAC"
)

var (
    adminRole 	  = rbac.NewRole("admin", rbac.CreatePermission|rbac.ReadPermission|rbac.UpdatePermission|rbac.DeletePermission)
    moderatorRole = rbac.NewRole("moderator", rbac.CreatePermission|rbac.ReadPermission|rbac.SelfUpdatePermission)
    userRole 	  = rbac.NewRole("user", rbac.SelfReadPermission|rbac.SelfUpdatePermission|rbac.SelfDeletePermission)
)

func main() {
    roles1 := []rbac.Role{userRole, adminRole}
    roles2 := []rbac.Role{userRole, moderatorRole}

    // This is the one who will perform the actions.
    user := rbac.NewEntity("user")

    // This is an action and the necessary permissions for it.
    // Note that this action is belong to the specific entity.
    act, err := user.NewAction("delete", rbac.DeletePermission)
    if err != nil {
        panic(err)
    }

    // [{user 168} {admin 85}]
    fmt.Println(roles1)
    // [{user 168} {moderator 37}]
    fmt.Println(roles2)

    // This is the one the actions will be performed on.
    cache := rbac.NewResource("cache")

    // Context of authorization
    ctx := rbac.NewAuthorizationContext(&user, act, cache)

    // Empty by default
    agp := rbac.NewActionGatePolicy()

    // Rule which require admin role for this context (user:delete:cache)
    rule := rbac.NewActionGateRule(&ctx, rbac.RequireActionGateEffect, []rbac.Role{adminRole})

    // Add rule (it must be valid and not exist in this policy, otherwise method will return an error)
    agpErr := agp.AddRule(rule)
    if agpErr != nil {
        panic(agpErr)
    }

    e := rbac.Authorize(&ctx, roles1, &agp)
    // Error: <nil>
    fmt.Println(e)

    e = rbac.Authorize(&ctx, roles2, &agp)
    // Error: Action has been denied by Action Gate Policy (Cuz roles2 doesn't have admin role)
    fmt.Println(e)
}
```

## Schema

`Schema` designed to help you organize roles in convenient human-readble form.

In it you can also select several roles as default.

`Schema` can be configured via JSON file and loaded using **LoadSchema(path string) (Schema, error)** function.

### Schema configuration example in JSON

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
    ],
    "resources": ["cache","user"],
    "entities": [
        {
            "name": "service",
            "action": [
                {
                    "name": "read",
                    "required-permissions": {
                        "read": true
                    }
                }
            ]
        },
        {
            "name": "user",
            "actions": [
                {
                    "name": "delete",
                    "required-permissions": {
                        "delete": true
                    }
                },
                {
                    "name": "self-delete",
                    "required-permissions": {
                        "self-delete": true
                    }
                },
                {
                    "name": "change-password",
                    "required-permissions": {
                        "update": true
                    }
                }
            ]
        }
    ],
    "action-gate-policy": [
        {
            "for": ["user"], (entities)
            "having": ["admin"], (roles)
            "apply": "require", (effect)
            "doing": ["delete"], (actions)
            "on": "cache" (resource)
        }
    ],
}
```

About `"action-gate-policy"` in this config - as you can see each rule can have several entities (`"for"`) and actions (`"doing"`).
It may looks a bit confusing, since context for rule requires only one entity and action, but here it works a bit different:
For each entity in `"for"` and actions in `"doing"` it will create and add a new rule. For example:

If you have 3 entities in `"for"` (e.g user, service, bot) and 1 action (delete) then will be created 3 different contexts and rules for them - _user:delete:cache_, _service:delete:cache_ and _bot:delete:cache_.

`"doing"` (actions) works similar, for the same 3 entities, but for 2 actions (delete, read) in total will be created 6 contexts and rules - _user:delete:cache_, _service:delete:cache_, _bot:delete:cache_, _user:read:cache_, _service:read:cache_ and _bot:read:cache_

> [!NOTE]
> If you're using a configuration file, the number of rules in the AGP for each schema is equal to:
>
> The number of entities (`"for"`) multiplied by the number of actions (`"doing"`)

## Host

`Host` originaly designed for applications with microservice architectures. Using it you can define multiple schemas.

Like each schema, `Host` can have roles and default roles, in this case they considered as global.
All schemas in `Host` must have all its global roles, but permissions for this roles may differ in each schema. And of course besides this global roles each schema can have its own 'local' roles.

> [!WARNING]
> Schema specific roles permissions will overwrite global roles permissions!

Like `Schema`, `Host` also can be loaded from JSON file using **LoadHost(path string) (Host, error)** function.

### Host configuration example in JSON

```json
{
    "default-roles": ["user"],
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
            "default-roles": ["moderator"],
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
            ...
        }
        ...
    ]
}
```
