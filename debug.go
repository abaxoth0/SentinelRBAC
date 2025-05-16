package rbac

import (
	"log"
	"sync/atomic"
)

var Debug atomic.Bool

func debugLog(msg string) {
    if Debug.Load() {
        log.Println(msg)
    }
}

