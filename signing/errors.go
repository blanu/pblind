package signing

import (
	"errors"
)

var ErrorPointNotOnCurve error = errors.New("Point not on Curve")
var ErrorInvalidSignerState error = errors.New("Signer is in invalid State")
var ErrorInvalidRequesterState error = errors.New("Signer is in invalid State")
var ErrorInvalidSignature error = errors.New("Signature is invalid")
