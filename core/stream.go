package core

import (
	"io"
	"net"
	"sync"
	"time"
)

// relay copies between left and right bidirectionally. Returns any error occurred.
func Relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now()) // unblock read on right
	}()

	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now()) // unblock read on left
	wg.Wait()

	if err1 != nil {
		err = err1
	}
	return err
}
