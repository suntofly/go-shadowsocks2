package shadowaead

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func newTestCipher(t *testing.T) cipher.AEAD {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestCipherReaderAuthentiationFailure(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := ioutil.NopCloser(strings.NewReader("Fails Authentication"))
	reader := newCipherReader(clientReader, cipher, payloadSizeMask)
	_, err := reader.ReadBlock(1)
	if err == nil {
		t.Fatalf("Expected authentication failure, got %v", err)
	}
}

func TestCipherReaderUnexpectedEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := ioutil.NopCloser(strings.NewReader("short"))
	server := newCipherReader(clientReader, cipher, payloadSizeMask)
	_, err := server.ReadBlock(10)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestCipherReaderEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := ioutil.NopCloser(strings.NewReader(""))
	server := newCipherReader(clientReader, cipher, payloadSizeMask)
	_, err := server.ReadBlock(10)
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
	_, err = server.ReadBlock(0)
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
}

func TestCipherReaderShortBuffer(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := ioutil.NopCloser(strings.NewReader(""))
	server := newCipherReader(clientReader, cipher, payloadSizeMask)
	_, err := server.ReadBlock(20 * 1024)
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected ErrShortBuffer, got %v", err)
	}
}

func TestCipherReaderGoodReads(t *testing.T) {
	cipher := newTestCipher(t)
	nonce := make([]byte, cipher.NonceSize())

	block1 := []byte("First Block")
	block2 := []byte("Second Block")
	expectedCipherSize := len(block1) + len(block2) + 2*cipher.Overhead()
	cipherText := make([]byte, expectedCipherSize)
	cipherText = cipher.Seal(cipherText[:0], nonce, block1, nil)
	nonce[0] = 1
	cipherText = cipher.Seal(cipherText, nonce, block2, nil)
	if len(cipherText) != expectedCipherSize {
		t.Fatalf("cipherText has size %v. Expected %v", len(cipherText), expectedCipherSize)
	}

	clientReader := ioutil.NopCloser(bytes.NewReader(cipherText))
	reader := newCipherReader(clientReader, cipher, payloadSizeMask)
	_, err := reader.ReadBlock(len(block1))
	if err != nil {
		t.Fatalf("Failed to read block1: %v", err)
	}
	_, err = reader.ReadBlock(0)
	if err != nil {
		t.Fatalf("Failed empty read: %v", err)
	}
	_, err = reader.ReadBlock(len(block2))
	if err != nil {
		t.Fatalf("Failed to read block2: %v", err)
	}
	_, err = reader.ReadBlock(0)
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
}

func TestCipherReaderClose(t *testing.T) {
	cipher := newTestCipher(t)

	pipeReader, pipeWriter := io.Pipe()
	server := newCipherReader(pipeReader, cipher, payloadSizeMask)
	result := make(chan error)
	go func() {
		_, err := server.ReadBlock(10)
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
	server := newCipherReader(pipeReader, cipher, payloadSizeMask)
	result := make(chan error)
	go func() {
		_, err := server.ReadBlock(10)
		result <- err
	}()
	pipeWriter.CloseWithError(fmt.Errorf("ERROR"))
	err := <-result
	if err == nil || err.Error() != "ERROR" {
		t.Fatalf("Unexpected error: %v", err)
	}
}
