package io

import (
	"io"
	"log"
)

func copyOneWay(writer io.Writer, writerClose func() error,
	reader io.Reader, readerClose func() error) (int64, error) {
	n, err := io.Copy(writer, reader)
	// Send FIN to indicate EOF
	writerClose()
	// Release reader resources
	readerClose()
	return n, err
}

// Relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func Relay(leftReader io.Reader, leftReaderClose func() error,
	leftWriter io.Writer, leftWriterClose func() error,
	rightReader io.Reader, rightReaderClose func() error,
	rightWriter io.Writer, rightWriterClose func() error) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := copyOneWay(rightWriter, rightWriterClose, leftReader, leftReaderClose)
		log.Printf("copyOneWay L->R done: %v %v", n, err)
		ch <- res{n, err}
	}()

	n, err := copyOneWay(leftWriter, leftWriterClose, rightReader, rightReaderClose)
	log.Printf("copyOneWay L<-R done: %v %v", n, err)
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
