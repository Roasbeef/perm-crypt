package aesffx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	numRounds = 10
)

// NewCipher creates a new cipher capable of encrypting and decrypting messages
// using the AES-FFX mode for format-preserving encryption.
func NewCipher(radix uint32, key, tweak []byte) (*FFXCipher, error) {
	var maxLength uint32 = (1 << 32) - 1

	if radix > 65536 {
		return nil, fmt.Errorf("radix must be between 2 and 2^16")
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("key length must be exactly 16 bytes")
	}
	if uint32(len(tweak)) > maxLength {
		return nil, fmt.Errorf("tweak length must be smaller than (2^32) - 1")
	}

	var minLength uint32 = 2
	if radix >= 10 {
		minLength = 8
	}

	return &FFXCipher{
		key:       key,
		tweak:     tweak,
		radix:     radix,
		minLength: minLength,
		maxLength: maxLength,
	}, nil
}

// FFXCipher represents the parameters needed for AES-FFX.
type FFXCipher struct {
	key   []byte
	tweak []byte
	radix uint32

	minLength uint32
	maxLength uint32
}

// Encrypt encrypts the given plaintext, producing ciphertext output.
func (f FFXCipher) Encrypt(src string) (string, error) {
	n := uint32(len(src))
	l := split(uint32(n))

	A := src[:l]
	B := src[l:]

	for i := 0; i < numRounds; i++ {
		fOut, err := f.feistelRound(n, f.tweak, i, B)
		if err != nil {
			return "", err
		}

		lmin := min(len(A), len(fOut))

		C, err := blockAddition(lmin, int(f.radix), A, fOut)
		if err != nil {
			return "", nil
		}

		A = B
		B = C
	}
	cipher := A + B
	return cipher, nil
}

// Decrypt decrypts the given ciphertext, producing plaintext output.
func (f FFXCipher) Decrypt(src string) (string, error) {
	n := uint32(len(src))
	l := split(uint32(n))

	A := src[:l]
	B := src[l:]

	for i := numRounds - 1; i > -1; i-- {
		C := B
		B = A

		fOut, err := f.feistelRound(n, f.tweak, i, B)
		if err != nil {
			return "", nil
		}

		lmin := min(len(C), len(fOut))

		A, err = blockSubtraction(lmin, int(f.radix), C, fOut)
		if err != nil {
			return "", nil
		}
	}
	plain := A + B
	return plain, nil
}

// blockAddition computes the block-wise radix addition of x and y.
func blockAddition(n, radix int, x, y string) (string, error) {
	xInt, err := strconv.ParseInt(x, radix, n*8)
	if err != nil {
		return "", err
	}
	yInt, err := strconv.ParseInt(y, radix, n*8)
	if err != nil {
		return "", err
	}

	blockSum := (xInt + yInt) % int64(math.Pow(float64(radix), float64(n)))

	out := strconv.FormatInt(blockSum, radix)
	if len(out) < n {
		out = strings.Repeat("0", n-len(out)) + out
	}
	return out, nil
}

// blockSubtraction computes the block-wise radix subtraction of x and y.
func blockSubtraction(n, radix int, x, y string) (string, error) {
	xInt, err := strconv.ParseInt(x, radix, n*8)
	if err != nil {
		return "", err
	}
	yInt, err := strconv.ParseInt(y, radix, n*8)
	if err != nil {
		return "", err
	}

	diff := xInt - yInt
	mod := int64(math.Pow(float64(radix), float64(n)))
	blockDiff := diff % mod
	if blockDiff < 0 {
		blockDiff += mod
	}

	out := strconv.FormatInt(blockDiff, radix)
	if len(out) < n {
		out = strings.Repeat("0", n-len(out)) + out
	}
	return out, nil
}

// feistalRound runs the given block through the modified feistel network.
func (f FFXCipher) feistelRound(msgLength uint32, tweak []byte, roundNum int, block string) (string, error) {
	t := len(tweak)
	beta := int(math.Ceil(float64(msgLength) / 2))

	// b = ceil(ceil(beta * log_2(radix)) / 8)
	b := int(math.Ceil(math.Ceil(float64(beta)*math.Log2(float64(f.radix))) / 8))

	// d = 4 * ceil(b/4)
	d := 4 * int(math.Ceil(float64(b)/4))

	var m int
	if roundNum%2 == 0 {
		m = int(math.Floor(float64(msgLength) / 2))
	} else {
		m = int(math.Ceil(float64(msgLength) / 2))
	}

	// p <- [vers] | [method] | [addition] | [radix] | [rnds(n)] | [split(n)] | [n] | [t]
	p, err := generateP(msgLength, f.radix, t)
	if err != nil {
		return "", err
	}

	// q <- tweak | [0]^((−t−b−1) mod 16) | [roundNum] | [numradix(B)]
	err = generateQ(block, p, tweak, t, b, roundNum, f.radix)
	if err != nil {
		return "", err
	}

	// Y = CBC-MAC_k(P || Q)
	bigY, err := cbcMac(f.key, p.Bytes())
	if err != nil {
		panic(err)
	}

	aes, err := aes.NewCipher(f.key)
	if err != nil {
		return "", nil
	}

	// Y <- first d+4 bytes of (Y | AESK(Y XOR [1]16) | AESK(Y XOR [2]16) | AESK(Y XOR [3]16)...)
	var yTemp bytes.Buffer
	c := bytes.NewBuffer(make([]byte, 16))
	i := 0
	yTemp.Write(bigY)
	for yTemp.Len() < (d + 4) {
		h, err := hex.DecodeString(strings.Repeat("0"+strconv.Itoa(i), 16))
		if err != nil {
			return "", nil
		}
		aes.Encrypt(c.Bytes(), xorBytes(bigY, h))
		yTemp.Write(c.Bytes())

		i++
		c.Reset()
	}

	// z = y mod r^m
	y := binary.BigEndian.Uint64(yTemp.Bytes())
	z := y % uint64(math.Pow(float64(f.radix), float64(m)))

	fOut := strconv.FormatUint(z, int(f.radix))
	// TODO(roasbeef): Factor out into padding funciton
	if len(fOut) < beta {
		fOut = strings.Repeat("0", beta-len(fOut)) + fOut
	}
	return fOut, nil
}

// split calculates the index to split the input string for our maximally
// balanced Feistel rounds.
func split(n uint32) uint32 {
	return uint32(math.Floor(float64(n) / 2))
}

// cbcMac computes the AES-CBC-MAC of the msg with the given key.
func cbcMac(key, msg []byte) ([]byte, error) {
	if len(msg)%16 != 0 {
		return nil, fmt.Errorf("message length must be a multiple of 16, got %v", len(msg))
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("key length must be exactly 128-bits")
	}

	// Create a new aes cipher from our key.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Initialize aes in CBC mode with a zero IV.
	y := make([]byte, 16, 16)
	cbc := cipher.NewCBCEncrypter(aesBlock, y)

	for i := 0; i < len(msg); i += 16 {
		x := msg[i:(i + 16)]
		cbc.CryptBlocks(y, x)
	}
	return y, nil
}

// xorBytes returns a new byte slice which is the result of XOR'ing each byte
// amongst the passed arguments.
func xorBytes(x, y []byte) []byte {
	out := make([]byte, len(x))
	for i := 0; i < len(x); i++ {
		out[i] = y[i] ^ x[i]
	}
	return out
}

// min returns the minimum of x and y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// generateP creates the first half of the IV our feistel round.
// This function returns a bytes.Buffer in so Q can easily be concatenated to
// it.
func generateP(mlen uint32, radix uint32, tweaklen int) (*bytes.Buffer, error) {
	var p bytes.Buffer
	p.Write([]byte{0x01})                                    // version
	p.Write([]byte{0x02})                                    // method
	p.Write([]byte{0x01})                                    // addition
	p.Write([]byte{0x00})                                    // 0 byte prefix to force 3 bytes
	err := binary.Write(&p, binary.BigEndian, uint16(radix)) // write 2 bytes of radix
	if err != nil {
		return nil, err
	}

	p.Write([]byte{0x0a})                                        // number of rounds is 10
	err = binary.Write(&p, binary.BigEndian, uint8(split(mlen))) // split
	if err != nil {
		return nil, err
	}

	err = binary.Write(&p, binary.BigEndian, mlen)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&p, binary.BigEndian, uint32(tweaklen))
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func generateQ(block string, buf *bytes.Buffer, tweak []byte, tlen int, blockLen int, i int, radix uint32) error {
	buf.Write(tweak)
	numPads := ((-1 * tlen) - blockLen - 1) % 16
	if numPads < 0 {
		numPads += 16
	}

	zeroPad, err := hex.DecodeString(strings.Repeat("00", numPads))
	if err != nil {
		return err
	}

	buf.Write(zeroPad)
	err = binary.Write(buf, binary.BigEndian, uint8(i))
	if err != nil {
		return err
	}

	var bBuffer bytes.Buffer
	radixBlock, err := strconv.ParseUint(block, int(radix), blockLen*8)
	if err != nil {
		return err
	}

	err = binary.Write(&bBuffer, binary.BigEndian, radixBlock)
	if err != nil {
		return err
	}

	buf.Write(bBuffer.Bytes()[bBuffer.Len()-blockLen:])

	return nil
}
