package signing

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"math/big"
)

type Signature struct {
	P *big.Int
	W *big.Int
	O *big.Int
	G *big.Int
}

type Message1 struct {
	Ax, Ay *big.Int
	Bx, By *big.Int
}

type Message2 struct {
	E *big.Int
}

type Message3 struct {
	R *big.Int
	C *big.Int
	S *big.Int
}

func LoadSignature(filename string) (*Signature, error) {
	data, readError := ioutil.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	var sig Signature
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decoder.Decode(&sig)

	return &sig, nil
}

func (sig Signature) Save(filename string) error {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(sig)
	if encodingError != nil {
		return encodingError
	}

	requestWriteError := ioutil.WriteFile(filename, buffer.Bytes(), 0644)
	if requestWriteError != nil {
		return requestWriteError
	}

	return nil
}

func Message1FromBytes(data []byte) (*Message1, error) {
	var msg1 Message1
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decoder.Decode(&msg1)

	return &msg1, nil
}

func (sig *Message1) Bytes() []byte {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(sig)
	if encodingError != nil {
		return nil
	}

	return buffer.Bytes()
}

func Message2FromBytes(data []byte) (*Message2, error) {
	var msg2 Message2
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decoder.Decode(&msg2)

	return &msg2, nil
}

func (sig *Message2) Bytes() []byte {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(sig)
	if encodingError != nil {
		return nil
	}

	return buffer.Bytes()
}

func Message3FromBytes(data []byte) (*Message3, error) {
	var msg3 Message3
	var buffer bytes.Buffer
	buffer.Write(data)
	decoder := gob.NewDecoder(&buffer)
	decoder.Decode(&msg3)

	return &msg3, nil
}

func (sig *Message3) Bytes() []byte {
	var buffer bytes.Buffer        // Stand-in for a network connection
	encoder := gob.NewEncoder(&buffer)
	encodingError := encoder.Encode(sig)
	if encodingError != nil {
		return nil
	}

	return buffer.Bytes()
}
