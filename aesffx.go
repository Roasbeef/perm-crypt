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

// NewCipher....
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

// FFXCipher....
type FFXCipher struct {
	key   []byte
	tweak []byte
	radix uint32

	minLength uint32
	maxLength uint32
}

// Encrypt...
func (f FFXCipher) Encrypt(src string) string {
	n := uint32(len(src))
	l := split(uint32(n))

	A := src[:l]
	B := src[l:]

	for i := 0; i < numRounds; i++ {
		fOut := f.feistelRound(n, f.tweak, i, B)
		lmin := min(len(A), len(fOut))

		C := blockAddition(lmin, int(f.radix), A, fOut)

		A = B
		B = C
	}
	cipher := A + B
	return cipher
}

// Decrypt...
func (f FFXCipher) Decrypt(src string) string {
	n := uint32(len(src))
	l := split(uint32(n))

	A := src[:l]
	B := src[l:]

	for i := numRounds - 1; i > -1; i-- {
		C := B
		B = A

		fOut := f.feistelRound(n, f.tweak, i, B)
		lmin := min(len(C), len(fOut))

		A = blockSubtraction(lmin, int(f.radix), C, fOut)
	}
	plain := A + B
	return plain
}

// blockAddition...
func blockAddition(n, radix int, x, y string) string {
	xInt, err := strconv.ParseInt(x, radix, n*8)
	if err != nil {
		panic(err)
	}
	yInt, err := strconv.ParseInt(y, radix, n*8)
	if err != nil {
		panic(err)
	}

	blockSum := (xInt + yInt) % int64(math.Pow(float64(radix), float64(n)))

	out := strconv.FormatInt(blockSum, radix)
	if len(out) < n {
		out = strings.Repeat("0", n-len(out)) + out
	}
	return out
}

// blockSubtraction...
func blockSubtraction(n, radix int, x, y string) string {
	xInt, err := strconv.ParseInt(x, radix, n*8)
	if err != nil {
		panic(err)
	}
	yInt, err := strconv.ParseInt(y, radix, n*8)
	if err != nil {
		panic(err)
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
	return out
}

// feistalRound
func (f FFXCipher) feistelRound(msgLength uint32, tweak []byte, roundNum int, block string) string {
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
	var p bytes.Buffer
	p.Write([]byte{0x01})                                      // version
	p.Write([]byte{0x02})                                      // method
	p.Write([]byte{0x01})                                      // addition
	p.Write([]byte{0x00})                                      // 0 byte prefix to force 3 bytes
	err := binary.Write(&p, binary.BigEndian, uint16(f.radix)) // write 2 bytes of radix
	maybeExit(err)
	p.Write([]byte{0x0a})                                             // number of rounds is 10
	err = binary.Write(&p, binary.BigEndian, uint8(split(msgLength))) // split
	maybeExit(err)
	err = binary.Write(&p, binary.BigEndian, msgLength)
	maybeExit(err)
	err = binary.Write(&p, binary.BigEndian, uint32(t))
	maybeExit(err)

	// q <- tweak | [0]^((−t−b−1) mod 16) | [roundNum] | [numradix(B)]
	var q bytes.Buffer
	q.Write(tweak)
	numPads := ((-1 * t) - b - 1) % 16
	if numPads < 0 {
		numPads += 16
	}
	zeroPad, err := hex.DecodeString(strings.Repeat("00", numPads))
	maybeExit(err)
	q.Write(zeroPad)
	err = binary.Write(&q, binary.BigEndian, uint8(roundNum))
	maybeExit(err)

	var bBuffer bytes.Buffer
	radixBlock, err := strconv.ParseUint(block, int(f.radix), b*8)
	err = binary.Write(&bBuffer, binary.BigEndian, radixBlock)
	maybeExit(err)
	q.Write(bBuffer.Bytes()[bBuffer.Len()-b:])
	maybeExit(err)

	// Y = CBC-MAC_k(P || Q)
	p.Write(q.Bytes())
	bigY, err := cbcMac(f.key, p.Bytes())
	if err != nil {
		panic(err)
	}

	aes, err := aes.NewCipher(f.key)
	if err != nil {
		panic(err)
	}

	// Y <- first d+4 bytes of (Y | AESK(Y XOR [1]16) | AESK(Y XOR [2]16) | AESK(Y XOR [3]16)...)
	var yTemp bytes.Buffer
	c := bytes.NewBuffer(make([]byte, 16))
	i := 0
	yTemp.Write(bigY)
	for yTemp.Len() < (d + 4) {
		h, err := hex.DecodeString(strings.Repeat("0"+strconv.Itoa(i), 16))
		if err != nil {
			panic(err)
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
	return fOut
}

// split...
func split(n uint32) uint32 {
	return uint32(math.Floor(float64(n) / 2))
}

// cbcMac...
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

// xorBytes....
func xorBytes(x, y []byte) []byte {
	out := make([]byte, len(x))
	for i := 0; i < len(x); i++ {
		out[i] = y[i] ^ x[i]
	}
	return out
}

func maybeExit(err error) {
	if err != nil {
		panic(err)
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
