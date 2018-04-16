package log

import (
	"flag"
	"log"
)

var verbose = false

func init() {
	flag.BoolVar(&verbose, "verbose", false, "verbose mode")
}

// VLogf logs the string if --verbose=true
func VLogf(f string, v ...interface{}) {
	if verbose {
		log.Printf(f, v...)
	}
}
