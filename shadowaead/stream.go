package shadowaead

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

// ciphWriter encrypts and signs blocks of plaintext, writing to the given Writer.
// This class is completely independent of the Shadowsocks protocol.
type cipherWriter struct {
	writer io.Writer
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

func newCipherWriter(writer io.Writer, aead cipher.AEAD, maxPayloadSize int) *cipherWriter {
	nonce := make([]byte, aead.NonceSize())
	buffer := make([]byte, maxPayloadSize+aead.Overhead())
	return &cipherWriter{writer: writer, cipher: aead, nonce: nonce, buf: buffer}
}

type shadowsocksWriter struct {
	cw *cipherWriter
	// Used to lazily initialize the shadowsocksWriter
	init func(*shadowsocksWriter) error
}

// NewShadowsocksWriter creates a Writer that encrypts the given Writer using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksWriter(writer io.Writer, ssCipher Cipher) io.Writer {
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
	toWrite := len(p)
	if toWrite > payloadSizeMask {
		toWrite = payloadSizeMask
	}
	buf := []byte{byte(toWrite >> 8), byte(toWrite)} // big-endian payload size
	_, err := sw.cw.WriteBlock(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to write payload size: %v", err)
	}
	_, err = sw.cw.WriteBlock(p)
	if err != nil {
		return 0, fmt.Errorf("failed to write payload: %v", err)
	}
	return toWrite, nil
}

type shadowsocksReader struct {
	reader   io.Reader
	ssCipher Cipher
	aead     cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte
}

// ShadowsocksReader is an io.Reader that also implements io.WriterTo to
// allow for piping the data without extra allocations and copies.
type ShadowsocksReader interface {
	io.Reader
	io.WriterTo
}

// NewShadowsocksReader creates a Reader that decrypts the given Reader using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksReader(reader io.Reader, ssCipher Cipher) ShadowsocksReader {
	return &shadowsocksReader{reader: reader, ssCipher: ssCipher}
}

// init reads the salt from the inner Reader and sets up the AEAD object
func (sr *shadowsocksReader) init() (err error) {
	if sr.aead == nil {
		salt := make([]byte, sr.ssCipher.SaltSize())
		if _, err := io.ReadFull(sr.reader, salt); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				err = fmt.Errorf("failed to read salt: %v", err)
			}
			return err
		}
		sr.aead, err = sr.ssCipher.Decrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		sr.nonce = make([]byte, sr.aead.NonceSize())
		sr.buf = make([]byte, payloadSizeMask+sr.aead.Overhead())
	}
	return nil
}

// ReadBlock reads and decrypts a single signed block of ciphertext.
// The block will match the given decryptedBlockSize.
// The returned slice is only valid until the next Read call.
func (sr *shadowsocksReader) readBlock(decryptedBlockSize int) ([]byte, error) {
	if err := sr.init(); err != nil {
		return nil, err
	}
	if decryptedBlockSize == 0 {
		// This read allows us to propagate EOF without consuming the reader
		_, err := sr.reader.Read(sr.buf[:0])
		return sr.buf[:0], err
	}
	cipherBlockSize := decryptedBlockSize + sr.aead.Overhead()
	if cipherBlockSize > cap(sr.buf) {
		return nil, io.ErrShortBuffer
	}
	buf := sr.buf[:cipherBlockSize]
	_, err := io.ReadFull(sr.reader, buf)
	if err != nil {
		return nil, err
	}
	buf, err = sr.aead.Open(buf[:0], sr.nonce, buf, nil)
	increment(sr.nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return buf, nil
}

func (sr *shadowsocksReader) Read(b []byte) (int, error) {
	n, err := sr.readLoop(b)
	return int(n), err
}

func (sr *shadowsocksReader) WriteTo(w io.Writer) (written int64, err error) {
	n, err := sr.readLoop(w)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

func (sr *shadowsocksReader) readLoop(w interface{}) (written int64, err error) {
	for {
		if len(sr.leftover) == 0 {
			buf, err := sr.readBlock(2)
			if err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					err = fmt.Errorf("failed to read payload size: %v", err)
				}
				return written, err
			}
			size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask
			payload, err := sr.readBlock(size)
			if err != nil {
				return written, fmt.Errorf("failed to read payload: %v", err)
			}
			sr.leftover = payload
		}
		switch v := w.(type) {
		case io.Writer:
			n, err := v.Write(sr.leftover)
			written += int64(n)
			sr.leftover = sr.leftover[n:]
			if err != nil {
				return written, err
			}
		case []byte:
			n := copy(v, sr.leftover)
			sr.leftover = sr.leftover[n:]
			return int64(n), nil
		}
	}
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

type connAdaptor struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (dc *connAdaptor) Read(b []byte) (int, error) {
	return dc.r.Read(b)
}

func (dc *connAdaptor) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, dc.r)
}

func (dc *connAdaptor) Write(b []byte) (int, error) {
	return dc.w.Write(b)
}

func (dc *connAdaptor) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(dc.w, r)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn {
	r := NewShadowsocksReader(c, ciph)
	w := NewShadowsocksWriter(c, ciph)
	return &connAdaptor{Conn: c, r: r, w: w}
}
