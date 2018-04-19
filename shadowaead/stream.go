package shadowaead

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"

	sio "github.com/shadowsocks/go-shadowsocks2/io"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

// ciphReader decrypts and authenticates blocks of ciphertext from the given Reader.
// This class is completely independent of the Shadowsocks protocol.
type cipherReader struct {
	reader io.ReadCloser
	cipher cipher.AEAD
	nonce  []byte
	buf    []byte
}

// ReadBlock reads and decrypts a single signed block of ciphertext.
// The block will match the given decryptedBlockSize.
// The returned slice is only valid until the next Read call.
func (cr *cipherReader) ReadBlock(decryptedBlockSize int) ([]byte, error) {
	if decryptedBlockSize == 0 {
		// This read allows us to propagate EOF without consuming the reader
		_, err := cr.reader.Read(cr.buf[:0])
		return cr.buf[:0], err
	}
	cipherBlockSize := decryptedBlockSize + cr.cipher.Overhead()
	if cipherBlockSize > cap(cr.buf) {
		return nil, io.ErrShortBuffer
	}
	buf := cr.buf[:cipherBlockSize]
	_, err := io.ReadFull(cr.reader, buf)
	if err != nil {
		return nil, err
	}
	buf, err = cr.cipher.Open(buf[:0], cr.nonce, buf, nil)
	increment(cr.nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return buf, nil
}

func (cr *cipherReader) Close() error {
	return cr.reader.Close()
}

// Creates a cipherReader that will read ciphertext from reader and use aead to decrypt.
// maxPayloadSize will determine the maximum size of a payload that it can read.
func newCipherReader(reader io.ReadCloser, aead cipher.AEAD, maxPayloadSize int) *cipherReader {
	nonce := make([]byte, aead.NonceSize())
	buffer := make([]byte, maxPayloadSize+aead.Overhead())
	return &cipherReader{reader: reader, cipher: aead, nonce: nonce, buf: buffer}
}

type shadowsocksReader struct {
	cr       *cipherReader
	leftover []byte
	init     func(*shadowsocksReader) error
}

// newShadowsocksReader creates a Reader that decrypts the given Reader using
// the shadowsocks protocol with the given shadowsocks cipher.
func newShadowsocksReader(reader io.ReadCloser, ssCipher Cipher) io.ReadCloser {
	init := func(sr *shadowsocksReader) error {
		salt := make([]byte, ssCipher.SaltSize())
		if _, err := io.ReadFull(reader, salt); err != nil {
			if err == io.EOF {
				return io.EOF
			}
			return fmt.Errorf("failed to read salt: %v", err)
		}
		aead, err := ssCipher.Decrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		sr.cr = newCipherReader(reader, aead, payloadSizeMask)
		sr.init = nil
		return nil
	}
	return &shadowsocksReader{init: init}
}

func (sr *shadowsocksReader) Read(b []byte) (int, error) {
	if sr.init != nil {
		if err := sr.init(sr); err != nil {
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("failed to initialize shadowsocksReader: %v", err)
		}
	}
	if len(sr.leftover) == 0 {
		buf, err := sr.cr.ReadBlock(2)
		if err == io.EOF {
			return 0, io.EOF
		} else if err != nil {
			return 0, fmt.Errorf("failed to read payload size: %v", err)
		}
		size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask
		payload, err := sr.cr.ReadBlock(size)
		if err != nil {
			return 0, fmt.Errorf("failed to read payload: %v", err)
		}
		sr.leftover = payload
	}
	n := copy(b, sr.leftover)
	sr.leftover = sr.leftover[n:]
	return n, nil
}

func (sr *shadowsocksReader) Close() error {
	// Note: sr.cr may be nil before initialization
	if sr.cr == nil {
		return nil
	}
	return sr.cr.Close()
}

// ciphWriter encrypts and signs blocks of plaintext, writing to the given Writer.
// This class is completely independent of the Shadowsocks protocol.
type cipherWriter struct {
	writer io.WriteCloser
	cipher cipher.AEAD
	nonce  []byte
	buf    []byte
}

// WriteBlock encrypts and writes the input buffer as one signed block.
func (cw *cipherWriter) WriteBlock(b []byte) (int, error) {
	// TODO: Should we allocate the seal buffer on the stack here
	// rather than on cipherWriter?
	out := cw.cipher.Seal(cw.buf[:0], cw.nonce, b, nil)
	increment(cw.nonce)
	_, err := cw.writer.Write(out)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (cw *cipherWriter) Close() error {
	return cw.writer.Close()
}

func newCipherWriter(writer io.WriteCloser, aead cipher.AEAD, maxPayloadSize int) *cipherWriter {
	nonce := make([]byte, aead.NonceSize())
	buffer := make([]byte, maxPayloadSize+aead.Overhead())
	return &cipherWriter{writer: writer, cipher: aead, nonce: nonce, buf: buffer}
}

type shadowsocksWriter struct {
	cw *cipherWriter
	// Used to lazily initialize the shadowsocksWriter
	init func(*shadowsocksWriter) error
}

// newShadowsocksWriter creates a Writer that encrypts the given Writer using
// the shadowsocks protocol with the given shadowsocks cipher.
func newShadowsocksWriter(writer io.WriteCloser, ssCipher Cipher) io.WriteCloser {
	init := func(sw *shadowsocksWriter) error {
		salt := make([]byte, ssCipher.SaltSize())
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("failed to generate salt: %v", err)
		}
		_, err := writer.Write(salt)
		if err != nil {
			return fmt.Errorf("failed to write salt: %v", err)
		}
		aead, err := ssCipher.Encrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		sw.cw = newCipherWriter(writer, aead, payloadSizeMask)
		sw.init = nil
		return nil
	}
	return &shadowsocksWriter{init: init}
}

func (sw *shadowsocksWriter) Write(p []byte) (int, error) {
	if sw.init != nil {
		if err := sw.init(sw); err != nil {
			return 0, fmt.Errorf("Failed to initialize shadowsocksWriter: %v", err)
		}
	}
	size := len(p)
	buf := []byte{byte(size >> 8), byte(size)} // big-endian payload size
	_, err := sw.cw.WriteBlock(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to write payload size: %v", err)
	}
	_, err = sw.cw.WriteBlock(p)
	if err != nil {
		return 0, fmt.Errorf("failed to write payload: %v", err)
	}
	return len(p), nil
}

func (sw *shadowsocksWriter) Close() error {
	// Note: sw.cw may be nil before initialization
	if sw.cw == nil {
		return nil
	}
	return sw.cw.Close()
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// All the code below is juggling the conversion
// net.Conn -> io.ReadCloser + io.WriteCloser -> net.Conn -> net.Conn + CloseReader + CloseWriter
// It would be cleaner if NewConn took a pair of ReadCloser, WriteCloser and returned a new pair.

type duplexConn struct {
	net.Conn
	r io.ReadCloser
	w io.WriteCloser
}

func (dc *duplexConn) Read(b []byte) (int, error) {
	return dc.r.Read(b)
}

func (dc *duplexConn) CloseRead() error {
	log.Println("[duplexConn] CloseRead()")
	return dc.r.Close()
}

func (dc *duplexConn) Write(b []byte) (int, error) {
	return dc.w.Write(b)
}

func (dc *duplexConn) CloseWrite() error {
	log.Println("[duplexConn] CloseWrite()")
	return dc.w.Close()
}

type readCloserAdaptor struct {
	io.Reader
}

func (a readCloserAdaptor) Close() error {
	log.Println("[readCloserAdaptor] Close()")
	return sio.CloseRead(a.Reader)
}

type writeCloserAdaptor struct {
	io.Writer
}

func (a writeCloserAdaptor) Close() error {
	log.Println("[writeCloserAdaptor] Close()")
	return sio.CloseWrite(a.Writer)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn {
	r := newShadowsocksReader(readCloserAdaptor{c}, ciph)
	w := newShadowsocksWriter(writeCloserAdaptor{c}, ciph)
	return &duplexConn{Conn: c, r: r, w: w}
}
