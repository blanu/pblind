package signing

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"math/big"
)

type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

type SecretKey struct {
	Curve  elliptic.Curve
	Scalar *big.Int
}

func (pk *PublicKey) String() string {
	return fmt.Sprintf("%S-Pk: (X = %S, Y = %S)", pk.Curve.Params().Name, pk.X, pk.Y)
}

func (sk *SecretKey) String() string {
	return fmt.Sprintf("%S-Sk: (S = %S)", sk.Curve.Params().Name, sk.Scalar)
}

func NewSecretKey(curve elliptic.Curve) (*SecretKey, error) {
	var err error
	var sk SecretKey
	sk.Curve = curve
	sk.Scalar, err = rand.Int(rand.Reader, curve.Params().N)
	return &sk, err
}

func LoadSecretKey(filename string) (*SecretKey, error) {
	data, readError := ioutil.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	var sk SecretKey
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decodeError := decoder.Decode(&sk)
	if decodeError != nil {
		return nil, decodeError
	}

	return &sk, nil
}

func LoadPublicKey(filename string) (*PublicKey, error) {
	data, readError := ioutil.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	var pk PublicKey
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decodeError := decoder.Decode(&pk)
	if decodeError != nil {
		return nil, decodeError
	}

	return &pk, nil
}

func SecretKeyFromBytes(curve elliptic.Curve, val []byte) *SecretKey {
	var sk SecretKey
	sk.Scalar = big.NewInt(0)
	sk.Scalar.SetBytes(val)
	sk.Curve = curve
	return &sk
}

func (sk *SecretKey) Bytes() []byte {
	return sk.Scalar.Bytes()
}

func (sk *SecretKey) GetPublicKey() *PublicKey {
	var pk PublicKey
	pk.X, pk.Y = sk.Curve.ScalarBaseMult(sk.Bytes())
	pk.Curve = sk.Curve
	return &pk
}

func (sk *SecretKey) Save(filename string) error {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(sk)
	if encodingError != nil {
		return encodingError
	}

	requestWriteError := ioutil.WriteFile(filename, buffer.Bytes(), 0644)
	if requestWriteError != nil {
		return requestWriteError
	}

	return nil
}

func (pk *PublicKey) Save(filename string) error {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(pk)
	if encodingError != nil {
		return encodingError
	}

	requestWriteError := ioutil.WriteFile(filename, buffer.Bytes(), 0644)
	if requestWriteError != nil {
		return requestWriteError
	}

	return nil
}