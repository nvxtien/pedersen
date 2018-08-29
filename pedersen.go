package pedersen

// the one way function here is scalar multiplication of curve points:
// C = rH + aG
// C is the curve point we will use as a commitment
// a is the value we commit to
// r is the randomness which provides hiding
// G is as already mentioned the publically agreed generator of the elliptic curve
// H is another curve point, for which nobody knows the discrete logarithm q: h = qG
// This unknowness is vital.

