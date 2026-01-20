package ldap

import (
	"io"
	log2 "log"
)

type Logger interface {
	Print(v ...any)
	Printf(format string, v ...any)
	SetOutput(w io.Writer)
}

var Log Logger = log2.Default()
