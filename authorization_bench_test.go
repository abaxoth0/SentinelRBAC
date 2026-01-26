package rbac

import (
	"sync"
	"testing"
)

// BenchmarkAuthorize_Concurrent benchmarks Authorize under high concurrency
// to verify that the atomic.Value approach scales well.
func BenchmarkAuthorize_Concurrent(b *testing.B) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	ctx := NewAuthorizationContext(&user, readAction, cache)
	roles := []Role{adminRole}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Authorize(&ctx, roles, nil)
		}
	})
}

// BenchmarkSetAuthzFunc_Concurrent benchmarks SetAuthzFunc under concurrent writes.
func BenchmarkSetAuthzFunc_Concurrent(b *testing.B) {
	customFunc := func(required, permitted Permissions) error {
		return nil
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			SetAuthzFunc(customFunc)
		}
	})
}

// BenchmarkAuthorize_MixedLoad benchmarks a realistic scenario with concurrent
// reads (Authorize) and occasional writes (SetAuthzFunc).
func BenchmarkAuthorize_MixedLoad(b *testing.B) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	ctx := NewAuthorizationContext(&user, readAction, cache)
	roles := []Role{adminRole}

	// Simulate occasional writes (1 write per 100 reads)
	var writeCounter int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Mostly reads
			_ = Authorize(&ctx, roles, nil)

			// Occasional write (every 100th operation)
			if writeCounter%100 == 0 {
				SetAuthzFunc(AuthorizeCRUDFunc)
			}
			writeCounter++
		}
	})
}

// BenchmarkAuthorize_HighConcurrency tests with many goroutines to verify
// that the atomic approach doesn't degrade under contention.
func BenchmarkAuthorize_HighConcurrency(b *testing.B) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	ctx := NewAuthorizationContext(&user, readAction, cache)
	roles := []Role{adminRole}

	b.ResetTimer()

	const goroutines = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < b.N/goroutines; j++ {
				_ = Authorize(&ctx, roles, nil)
			}
		}()
	}

	wg.Wait()
}

