package rbac

import (
	"sync"
	"testing"
)

// TestSetAuthzFunc_Concurrent tests that SetAuthzFunc is thread-safe.
func TestSetAuthzFunc_Concurrent(t *testing.T) {
	const goroutines = 100
	const iterations = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrently set different authorization functions
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				customFunc := func(required, permitted Permissions) error {
					// Simple function that always allows if required is 0
					if required == 0 {
						return nil
					}
					return ErrInsufficientPermissions
				}
				SetAuthzFunc(customFunc)
			}
		}(i)
	}

	wg.Wait()

	// Verify the function was set (no panic means it worked)
	// The actual function doesn't matter, just that we didn't have a race
	SetAuthzFunc(AuthorizeCRUDFunc)
}

// TestAuthorize_Concurrent tests that Authorize is thread-safe when
// SetAuthzFunc is called concurrently.
func TestAuthorize_Concurrent(t *testing.T) {
	const goroutines = 50

	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	ctx := NewAuthorizationContext(&user, readAction, cache)
	roles := []Role{adminRole}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Concurrently call SetAuthzFunc
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			SetAuthzFunc(AuthorizeCRUDFunc)
		}()
	}

	// Concurrently call Authorize
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := Authorize(&ctx, roles, nil)
			// Should either succeed or fail consistently, not panic
			_ = err
		}()
	}

	wg.Wait()
}

