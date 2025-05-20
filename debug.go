package rbac

import (
	"log"
	"sync/atomic"
)

// Package will work in debug mode if true
var Debug atomic.Bool

func debugLog(msg string) {
    if Debug.Load() {
        log.Println(msg)
    }
}

