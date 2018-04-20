package shadowaead

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func newTestCipher(t *testing.T) Cipher {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	cipher, err := Chacha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestCipherReaderAuthentiationFailure(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("Fails Authentication")
	reader := NewShadowsocksReader(clientReader, cipher)
	_, err := reader.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("Expected authentication failure, got %v", err)
	}
}

func TestCipherReaderUnexpectedEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("short")
	server := NewShadowsocksReader(clientReader, cipher)
	_, err := server.Read(make([]byte, 10))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestCipherReaderEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("")
	server := NewShadowsocksReader(clientReader, cipher)
	_, err := server.Read(make([]byte, 10))
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
	_, err = server.Read([]byte{})
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
}

// TODO: Re-write this test
// func TestCipherReaderGoodReads(t *testing.T) {
// 	cipher := newTestCipher(t)
// 	nonce := make([]byte, cipher.NonceSize())

// 	block1 := []byte("First Block")
// 	block2 := []byte("Second Block")
// 	expectedCipherSize := len(block1) + len(block2) + 2*cipher.Overhead()
// 	cipherText := make([]byte, expectedCipherSize)
// 	cipherText = cipher.Seal(cipherText[:0], nonce, block1, nil)
// 	nonce[0] = 1
// 	cipherText = cipher.Seal(cipherText, nonce, block2, nil)
// 	if len(cipherText) != expectedCipherSize {
// 		t.Fatalf("cipherText has size %v. Expected %v", len(cipherText), expectedCipherSize)
// 	}

// 	reader := NewShadowsocksReader(bytes.NewReader(cipherText), cipher)
// 	_, err := reader.ReadBlock(len(block1))
// 	if err != nil {
// 		t.Fatalf("Failed to read block1: %v", err)
// 	}
// 	_, err = reader.ReadBlock(0)
// 	if err != nil {
// 		t.Fatalf("Failed empty read: %v", err)
// 	}
// 	_, err = reader.ReadBlock(len(block2))
// 	if err != nil {
// 		t.Fatalf("Failed to read block2: %v", err)
// 	}
// 	_, err = reader.ReadBlock(0)
// 	if err != io.EOF {
// 		t.Fatalf("Expected EOF, got %v", err)
// 	}
// }

func TestCipherReaderClose(t *testing.T) {
	cipher := newTestCipher(t)

	pipeReader, pipeWriter := io.Pipe()
	server := NewShadowsocksReader(pipeReader, cipher)
	result := make(chan error)
	go func() {
		_, err := server.Read(make([]byte, 10))
		result <- err
	}()
	pipeWriter.Close()
	err := <-result
	if err != io.EOF {
		t.Fatalf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestCipherReaderCloseError(t *testing.T) {
	cipher := newTestCipher(t)

	pipeReader, pipeWriter := io.Pipe()
	server := NewShadowsocksReader(pipeReader, cipher)
	result := make(chan error)
	go func() {
		_, err := server.Read(make([]byte, 10))
		result <- err
	}()
	pipeWriter.CloseWithError(fmt.Errorf("xx!!ERROR!!xx"))
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "xx!!ERROR!!xx") {
		t.Fatalf("Unexpected error: %v", err)
	}
}
