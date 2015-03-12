package aesffx

import (
	"bytes"
	"crypto/aes"
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

// TODO(roasbeef): Tweak??
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
	tweak []byte // TODO(roasbeef): de-couple tweak?
	radix uint32 // TODO(roasbeef): make unit16?

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
		C := blockAddition(int(l), int(f.radix), A, f.feistalRound(n, f.tweak, i, B))

		A = B
		B = C
	}
	cipher := A + B
	/*	if len(cipher) != len(src) {
		fmt.Println("redo", cipher)
		goto redo
	}*/
	return cipher
}

// Decrypt...
func (f FFXCipher) Decrypt(src string) string {
	n := uint32(len(src))
	l := split(uint32(n))

	A := src[:l]
	B := src[l:]

	for i := numRounds; i > 0; i-- {
		C := B
		B = A

		A = blockSubtraction(int(l), int(f.radix), C, f.feistalRound(n, f.tweak, i, B))
	}
	plain := A + B
	return plain
}

// blockAddition...
func blockAddition(n, radix int, x, y string) string {
	xInt, err := strconv.ParseUint(x, radix, n*8)
	if err != nil {
		panic(err)
	}
	yInt, err := strconv.ParseUint(y, radix, n*8)
	if err != nil {
		panic(err)
	}

	blockSum := (xInt + yInt) % uint64(math.Pow(float64(radix), float64(n)))
	return strconv.FormatUint(blockSum, radix)
}

// blockSubtraction...
func blockSubtraction(n, radix int, x, y string) string {
	// Use hex.Encode??
	xInt, err := strconv.ParseUint(x, radix, n*8)
	if err != nil {
		panic(err)
	}
	yInt, err := strconv.ParseUint(y, radix, n*8)
	if err != nil {
		panic(err)
	}

	diff := xInt - yInt
	mod := uint64(math.Pow(float64(radix), float64(n)))
	blockDiff := diff % mod
	if blockDiff < 0 {
		blockDiff += mod
	}
	return strconv.FormatUint(blockDiff, radix)
}

// feistalRound...
func (f FFXCipher) feistalRound(msgLength uint32, tweak []byte, roundNum int, block string) string {
	t := len(tweak)
	beta := int(math.Ceil(float64(msgLength / 2)))

	// b = ceil(ceil(beta * log_2(radix)) / 8)
	b := int(math.Ceil(
		math.Ceil(float64(
			int(beta)*int(math.Log2(float64(f.radix))),
		)) / 8,
	))
	// d = 4 * ceil(b/4)
	d := 4 * int(math.Ceil(float64(b/4)))

	var m int
	if roundNum%2 == 0 {
		m = int(math.Floor(float64(msgLength / 2)))
	} else {
		m = int(math.Ceil(float64(msgLength / 2)))
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
	radixBlock, err := strconv.ParseUint(block, int(f.radix), b*8) // TODO(roasbeef): Proper size?
	err = binary.Write(&bBuffer, binary.BigEndian, radixBlock)
	maybeExit(err)
	q.Write(bBuffer.Bytes()[:b])
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

	// Should be uint???
	return strconv.FormatUint(z, int(f.radix))
}

// split...
func split(n uint32) uint32 {
	return uint32(math.Floor(float64(n / 2)))
}

// cbcMac...
// TODO(roasbeef): TESTS!!!
func cbcMac(key, msg []byte) ([]byte, error) {
	if len(msg)%16 != 0 {
		return nil, fmt.Errorf("message length must be a multiple of 16, got %v", len(msg))
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("key length must be exactly 128-bits")
	}

	// Create a new aes cipher from our key.
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	y := make([]byte, 16, 16)
	msgLength := len(msg) / 16

	for i := 0; i < msgLength; i += 16 {
		// y = AES_ECB(m_i XOR y)
		x := msg[i:(i + 16)]
		aes.Encrypt(y, xorBytes(x, y))
	}

	return y, nil
}

// xorBytes....
func xorBytes(x, y []byte) []byte {
	out := make([]byte, len(y))
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
