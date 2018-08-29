package pedersen

import (
	"testing"
	"fmt"
	"crypto/rand"
	"bytes"
	"golang.org/x/crypto/bn256"
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

	pb, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(b).Marshal())
	qb, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(b).Marshal())

	pc, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(c).Marshal())
	qc, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(c).Marshal())

	k1 := bn256.Pair(pb, qc)
	k1.ScalarMult(k1, a)
	k1Bytes := k1.Marshal()

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