package signing

// https://link.springer.com/content/pdf/10.1007/3-540-44598-6_17.pdf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"io/ioutil"
	"math/big"
)

const (
	stateSignerFresh = iota
	stateSignerMsg1Created
	stateSignerMsg2Processed
	stateSignerMsg3Created
)

type StateSigner struct {
	State int
	Info  Info           // shared Info for exchange
	Curve elliptic.Curve // domain
	Sk    SecretKey      // secret key
	U     *big.Int       // Scalar
	S     *big.Int       // Scalar
	D     *big.Int       // Scalar
	E     *big.Int       // Scalar
}

func CreateSigner(sk SecretKey, info Info) (*StateSigner, error) {

	st := StateSigner{
		State: stateSignerFresh,
		Sk:    sk,
		Curve: sk.Curve,
		Info:  info,
	}

	order := st.Curve.Params().N

	var err error

	if st.U, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.S, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.D, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	return &st, nil
}

func LoadSigner(filename string) (*StateSigner, error) {
	data, readError := ioutil.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	var signer StateSigner
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decodeError := decoder.Decode(&signer)
	if decodeError != nil {
		return nil, decodeError
	}

	return &signer, nil
}

func (st *StateSigner) CreateMessage1() (Message1, error) {

	var msg Message1

	if st.State != stateSignerFresh {
		return msg, ErrorInvalidSignerState
	}

	/* a = U * g
	 * b = S * g + D * z
	 */

	t1x, t1y := st.Curve.ScalarMult(st.Info.X, st.Info.Y, st.D.Bytes())
	t2x, t2y := st.Curve.ScalarBaseMult(st.S.Bytes())

	msg.Ax, msg.Ay = st.Curve.ScalarBaseMult(st.U.Bytes())
	msg.Bx, msg.By = st.Curve.Add(t1x, t1y, t2x, t2y)

	st.State = stateSignerMsg1Created

	return msg, nil
}

func (st *StateSigner) ProcessMessage2(msg Message2) error {
	if st.State != stateSignerMsg1Created {
		return ErrorInvalidSignerState
	}

	st.E = msg.E
	st.State = stateSignerMsg2Processed
	return nil
}

func (st *StateSigner) CreateMessage3() (Message3, error) {

	if st.State != stateSignerMsg2Processed {
		return Message3{}, ErrorInvalidSignerState
	}

	params := st.Curve.Params()

	c := big.NewInt(0)
	c.Sub(st.E, st.D)
	c.Mod(c, params.N)

	r := big.NewInt(0)
	r.Mul(c, st.Sk.Scalar)
	r.Sub(st.U, r)
	r.Mod(r, params.N)

	st.State = stateSignerMsg3Created

	return Message3{R: r, C: c, S: st.S}, nil
}

func (signer *StateSigner) Save(filename string) error {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(signer)
	if encodingError != nil {
		return encodingError
	}

	requestWriteError := ioutil.WriteFile(filename, buffer.Bytes(), 0644)
	if requestWriteError != nil {
		return requestWriteError
	}

	return nil
}