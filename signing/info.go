package signing

import (
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"math/big"
)

type Info struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

func (info Info) String() string {
	return fmt.Sprintf("(%S %S)", info.X, info.Y)
}

func (info1 Info) Equals(info2 Info) bool {
	cmp1 := subtle.ConstantTimeCompare(info1.X.Bytes(), info2.X.Bytes())
	cmp2 := subtle.ConstantTimeCompare(info1.Y.Bytes(), info2.Y.Bytes())
	return subtle.ConstantTimeEq(int32(cmp1), int32(cmp2)) == 1
}

func CompressInfo(curve elliptic.Curve, info []byte) (c Info, err error) {
	c.X, c.Y, err = hashToPoint(curve, info)
	return c, err
}
