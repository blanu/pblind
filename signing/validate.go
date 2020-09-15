package signing

import (
	"crypto/elliptic"
	"crypto/subtle"
	"math/big"
)

func (pk PublicKey) Check(sig Signature, info Info, msg []byte) bool {

	curve := pk.Curve
	params := curve.Params()

	lhs := big.NewInt(0)
	lhs.Add(sig.W, sig.G)
	lhs.Mod(lhs, params.N)

	hin := make([]byte, 0, 1024)

	// || p*g + w*Y

	func() {
		x1, y1 := curve.ScalarBaseMult(sig.P.Bytes())
		x2, y2 := curve.ScalarMult(pk.X, pk.Y, sig.W.Bytes())
		x3, y3 := curve.Add(x1, y1, x2, y2)
		hin = append(hin, elliptic.Marshal(curve, x3, y3)...)
	}()

	// || o*g + g*z

	func() {
		x1, y1 := curve.ScalarBaseMult(sig.O.Bytes())
		x2, y2 := curve.ScalarMult(info.X, info.Y, sig.G.Bytes())
		x3, y3 := curve.Add(x1, y1, x2, y2)
		hin = append(hin, elliptic.Marshal(curve, x3, y3)...)
	}()

	// || z || msg

	hin = append(hin, elliptic.Marshal(curve, info.X, info.Y)...)
	hin = append(hin, msg...)

	hsh := hashToScalar(curve, hin)
	cmp := subtle.ConstantTimeCompare(lhs.Bytes(), hsh.Bytes())

	return cmp == 1
}
