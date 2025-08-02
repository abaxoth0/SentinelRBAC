package rbac

import (
	"errors"
	"log"
	"os"
)

type debugger struct {
	Enabled bool
	logger *log.Logger
}

func (d *debugger) Log(v ...any) {
	if d.Enabled {
		d.logger.Println(v...)
	}
}

func (d *debugger) SetLogger(logger *log.Logger) error {
	if logger == nil {
		return errors.New("Debug logger can't be nil")
	}

	d.logger = logger

	return nil
}

var Debug = &debugger{
	logger: log.New(
		os.Stdout,
		"[ RBAC:DEBUG ] ",
		log.Ldate|log.Ltime,
	),
}

