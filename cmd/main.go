package main

import (
	"fmt"

	rbac "github.com/abaxoth0/SentinelRBAC"
)

func main() {
	rbac.Debug.Enabled = true

	_, err := rbac.LoadHost("RBAC.json")

	if err != nil {
		println("hit (from main.go)")
		panic(err)
	}

	// fmt.Println(len(host.Schemas))
	// fmt.Println(host.Schemas[0].ActionGatePolicy)
	// fmt.Println("==============================")

	example()

	// fmt.Printf("schema count: %d\n", len(Host.Schemas))
	// _, e := Host.GetSchema("2fd9f71c-4ced-4607-af47-7e8cc21725a9")
	// if e != nil {
	//     panic(e)
	// }

	// Host
	// fmt.Printf("schemas: %v\n", (Host.Schemas))
	// fmt.Printf("roles: %v\n", (Host.Roles))
	// fmt.Printf("default-roles: %v\n", (Host.DefaultRoles))

	// Schema
	// fmt.Printf("name: %v\n", (schema.Name))
	// fmt.Printf("id: %v\n", (schema.ID))
	// fmt.Printf("roles: %v\n", (schema.Roles))
	// fmt.Printf("default-roles: %v\n", (schema.DefaultRoles))

	println("OK")
}

var (
	adminRole     = rbac.NewRole("admin", rbac.CreatePermission|rbac.ReadPermission|rbac.UpdatePermission|rbac.DeletePermission)
	moderatorRole = rbac.NewRole("moderator", rbac.CreatePermission|rbac.ReadPermission|rbac.SelfUpdatePermission)
	userRole      = rbac.NewRole("user", rbac.SelfReadPermission|rbac.SelfUpdatePermission|rbac.SelfDeletePermission)
)

func example() {
	roles1 := []rbac.Role{userRole, adminRole}
	roles2 := []rbac.Role{userRole, moderatorRole}

	user := rbac.NewEntity("user")

	// This is required permissions for this action
	act, err := user.NewAction("delete", rbac.DeletePermission)
	if err != nil {
		panic(err)
	}

	fmt.Println(roles1)
	fmt.Println(roles2)

	cache := rbac.NewResource("cache")

	ctx := rbac.NewAuthorizationContext(&user, act, cache)

	// Create empty policy
	agp := rbac.NewActionGatePolicy()

	// Rule which require admin role for this context (user:delete:cache)
	rule := rbac.NewActionGateRule(&ctx, rbac.RequireActionGateEffect, []rbac.Role{adminRole})

	// Add rule (it must be valid and not already exist in policy, otherwise this method will return an error)
	agpErr := agp.AddRule(rule)
	if agpErr != nil {
		panic(agpErr)
	}

	e := rbac.Authorize(&ctx, roles1, &agp)
	// Error: Action has been denied by Action Gate Policy
	fmt.Println(e)

	e = rbac.Authorize(&ctx, roles2, &agp)
	// Error: Insufficient permissions to perform this action
	fmt.Println(e)
}
