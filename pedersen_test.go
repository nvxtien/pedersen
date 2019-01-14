package pedersen

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"testing"
)

func TestPlayBN256(t *testing.T) {

	a, _ := rand.Int(rand.Reader, bn256.Order)
	b, _ := rand.Int(rand.Reader, bn256.Order)
	c, _ := rand.Int(rand.Reader, bn256.Order)

	fmt.Print("\n======== Private keys (a,b,c) ============")
	fmt.Printf("\na: %d", a)
	fmt.Printf("\nb: %d", b)
	fmt.Printf("\nc: %d", c)

	pa, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(a).Marshal())
	qa, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(a).Marshal())
	fmt.Print("\n======== Alice's public key pair ============")
	fmt.Printf("\nPa (generated from G1): %s", pa)
	fmt.Printf("\nQa: (generated from G2) %s", qa)

	fmt.Printf("\nhex    %s\n", toHex(qa.Marshal()))

	fmt.Printf("\nhex    %s\n", toHex([]byte("FFFF")))
	fmt.Printf("\nhex    %d\n", len(toHex([]byte("FFFF"))))

	pb, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(b).Marshal())
	qb, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(b).Marshal())

	pc, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(c).Marshal())
	qc, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(c).Marshal())

	k1 := bn256.Pair(pb, qc)
	k1.ScalarMult(k1, a)

	k1Bytes := k1.Marshal()
	fmt.Printf("\nQa: (generated from k1Bytes Marshal) %d ", len(k1Bytes))

	k11 := bn256.Pair(pc, qb)
	k11.ScalarMult(k11, a)
	k11Bytes := k11.Marshal()
	fmt.Printf("\nQa: (generated from k1Bytes Marshal) %d ", len(k11Bytes))

	if !bytes.Equal(k1Bytes, k11Bytes) {
		t.Errorf("\nk1 != k11")
	}

	k2 := bn256.Pair(pc, qa)
	k2.ScalarMult(k2, b)
	k2Bytes := k2.Marshal()

	k3 := bn256.Pair(pa, qb)
	k3.ScalarMult(k3, c)

	k3Bytes := k3.Marshal()

	if !bytes.Equal(k1Bytes, k2Bytes) || !bytes.Equal(k2Bytes, k3Bytes) {
		t.Errorf("keys didn't agree")
	}

	fmt.Printf("\n")
}

func TestLinearConstraints(t *testing.T) {
	// 2p + 3q = 5r

	G := new(bn256.G1)

	p, _ := new(big.Int).SetString("30", 10)
	P := G.ScalarBaseMult(p)

	_2P := new(bn256.G1).Add(P, P)

	q, _ := new(big.Int).SetString("20", 10)
	Q := G.ScalarBaseMult(q)

	_2Q := new(bn256.G1).Add(Q, Q)
	_3Q := new(bn256.G1).Add(_2Q, Q)

	sum := new(bn256.G1).Add(_2P, _3Q)

	r, _ := new(big.Int).SetString("64", 10)
	R := G.ScalarBaseMult(r)

	_2R := new(bn256.G1).Add(R, R)
	_4R := new(bn256.G1).Add(_2R, _2R)
	_5R := new(bn256.G1).Add(_4R, R)

	sumBytes := sum.Marshal()

	_5RBytes := _5R.Marshal()

	if !bytes.Equal(sumBytes, _5RBytes) {
		t.Errorf("not equal")
	}
}

func toHex(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}
