package io

import (
	"io"
	"log"
)

type closeReader interface {
	CloseRead() error
}

func CloseRead(r interface{}) error {
	switch rt := r.(type) {
	case closeReader:
		log.Println("[CloseRead] a.CloseRead()")
		return rt.CloseRead()
	case io.Closer:
		log.Println("[CloseRead] a.Close()")
		return rt.Close()
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func CloseWrite(w interface{}) error {
	switch wt := w.(type) {
	case closeWriter:
		log.Println("[CloseWrite] a.CloseWrite()")
		return wt.CloseWrite()
	case io.Closer:
		log.Println("[CloseWrite] a.Close()")
		return wt.Close()
	}
	return nil
}

// Relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func Relay(left, right io.ReadWriteCloser) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		CloseWrite(right)
		if n == 0 || err != nil {
			CloseRead(right)
		}
		log.Printf("copyClose L->R done: %v %v", n, err)
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	CloseWrite(left)
	if n == 0 || err != nil {
		CloseRead(left)
	}
	log.Printf("copyClose L<-R done: %v %v", n, err)
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
