package signing

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"io/ioutil"
	"math/big"
)

const (
	stateRequesterFresh = iota
	stateRequesterMsg1Processed
	stateRequesterMsg2Created
	stateRequesterMsg3Processed
)

type StateRequester struct {
	State   int
	Info    Info           // shared Info for exchange
	Message []byte         // Message to sign
	Curve   elliptic.Curve // domain
	Pk      *PublicKey
	T1      *big.Int  // Scalar
	T2      *big.Int  // Scalar
	T3      *big.Int  // Scalar
	T4      *big.Int  // Scalar
	E       *big.Int  // Scalar
	Sig     Signature // final signature
}

func CreateRequester(pk *PublicKey, info Info, message []byte) (*StateRequester, error) {

	st := StateRequester{
		State:   stateRequesterFresh,
		Info:    info,
		Pk:      pk,
		Curve:   pk.Curve,
		Message: message,
	}

	order := st.Curve.Params().N

	var err error

	if st.T1, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.T2, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.T3, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.T4, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	return &st, nil
}

func LoadRequester(filename string) (*StateRequester, error) {
	data, readError := ioutil.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	var requester StateRequester
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decoder.Decode(&requester)

	return &requester, nil
}

func (st *StateRequester) ProcessMessage1(msg Message1) error {

	if st.State != stateRequesterFresh {
		return ErrorInvalidRequesterState
	}

	if !st.Curve.IsOnCurve(msg.Ax, msg.Ay) {
		return ErrorPointNotOnCurve
	}

	if !st.Curve.IsOnCurve(msg.Bx, msg.By) {
		return ErrorPointNotOnCurve
	}

	st.E = func() *big.Int {

		// alpha = a + T1 * g + T2 * Y

		alphax, alphay := func() (*big.Int, *big.Int) {
			t1x, t1y := st.Curve.ScalarBaseMult(st.T1.Bytes())
			t2x, t2y := st.Curve.ScalarMult(st.Pk.X, st.Pk.Y, st.T2.Bytes())
			alx, aly := st.Curve.Add(msg.Ax, msg.Ay, t1x, t1y)
			return st.Curve.Add(alx, aly, t2x, t2y)
		}()

		// beta = b + T3 * g + T4 * z

		betax, betay := func() (*big.Int, *big.Int) {
			t3x, t3y := st.Curve.ScalarBaseMult(st.T3.Bytes())
			t4x, t4y := st.Curve.ScalarMult(st.Info.X, st.Info.Y, st.T4.Bytes())
			bex, bey := st.Curve.Add(msg.Bx, msg.By, t3x, t3y)
			return st.Curve.Add(bex, bey, t4x, t4y)
		}()

		// hash to Scalar

		var buff []byte

		buff = elliptic.Marshal(st.Curve, alphax, alphay)
		buff = append(buff, elliptic.Marshal(st.Curve, betax, betay)...)
		buff = append(buff, elliptic.Marshal(st.Curve, st.Info.X, st.Info.Y)...)
		buff = append(buff, st.Message...)

		return hashToScalar(st.Curve, buff)
	}()

	st.E.Sub(st.E, st.T2)
	st.E.Sub(st.E, st.T4)
	st.E.Mod(st.E, st.Curve.Params().N)

	st.State = stateRequesterMsg1Processed

	return nil
}

func (st *StateRequester) CreateMessage2() (Message2, error) {
	if st.State != stateRequesterMsg1Processed {
		return Message2{}, ErrorInvalidRequesterState
	}
	st.State = stateRequesterMsg2Created
	return Message2{E: st.E}, nil
}

func (st *StateRequester) ProcessMessage3(msg Message3) error {

	if st.State != stateRequesterMsg2Created {
		return ErrorInvalidRequesterState
	}

	params := st.Curve.Params()

	// infer D

	d := big.NewInt(0)
	d.Sub(st.E, msg.C)
	d.Mod(d, params.N)

	// calculate signature

	p := big.NewInt(0)
	p.Add(msg.R, st.T1)
	p.Mod(p, params.N)

	w := big.NewInt(0)
	w.Add(msg.C, st.T2)
	w.Mod(w, params.N)

	o := big.NewInt(0)
	o.Add(msg.S, st.T3)
	o.Mod(o, params.N)

	g := big.NewInt(0)
	g.Add(d, st.T4)
	g.Mod(g, params.N)

	st.Sig = Signature{
		P: p, W: w,
		O: o, G: g,
	}

	// validate signature

	if !st.Pk.Check(st.Sig, st.Info, st.Message) {
		return ErrorInvalidSignature
	}

	st.State = stateRequesterMsg3Processed

	return nil
}

func (st *StateRequester) Signature() (Signature, error) {

	if st.State != stateRequesterMsg3Processed {
		return Signature{}, ErrorInvalidRequesterState
	}

	return st.Sig, nil
}

func (st *StateRequester) Save(filename string) error {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(st)
	if encodingError != nil {
		return encodingError
	}

	requestWriteError := ioutil.WriteFile(filename, buffer.Bytes(), 0644)
	if requestWriteError != nil {
		return requestWriteError
	}

	return nil
}
