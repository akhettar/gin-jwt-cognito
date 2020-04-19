package jwt

import (
	"io/ioutil"
	"log"
	"os"
)

var (
	// Trace logger
	Trace *log.Logger

	// Info logger
	Info *log.Logger

	// Warning logger
	Warning *log.Logger

	// Error logger
	Error *log.Logger
)

func init() {
	Trace = log.New(ioutil.Discard,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(os.Stdout,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(os.Stdout,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(os.Stdout,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}
