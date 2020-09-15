package main

import (
	"crypto/elliptic"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/blanu/pblind/signing"
	"net"
	"os"
)

func main() {
	println("pblind")
	gob.Register(elliptic.P256())

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "pblind v0.0.1\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Usage:\n\tpblind -client -state [statedir] -version 2 -transports [transport1,transport2,...]\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Example:\n\tpblind -client -state state -version 2 -transports obfs2\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Flags:\n\n")
		flag.PrintDefaults()
	}

	genkeys := flag.Bool("genkeys", false, "Generate signing keys")
	request := flag.Bool("request", false, "Request a signature")
	message := flag.String("message", "", "Message for the signature request")
	info := flag.String("info", "", "Info for the signature request")
	sign := flag.Bool("sign", false, "Sign a request")
	stage1 := flag.Bool("signerStage1", false, "Process request, signerStage1")
	stage2 := flag.Bool("signerStage2", false, "Process request, signerStage2")
	stage3 := flag.Bool("signerStage3", false, "Process request, signerStage3")
	check := flag.Bool("check", false, "Check signature")
	server := flag.Bool("server", false, "Run a signature server")
	client := flag.Bool("client", false, "Run a signature requester client")
	demo := flag.Bool("demo", false, "Test client and server on the same machine")

	flag.Parse()

	if *genkeys {
		println("Generating keys...")

		if _, err := os.Stat("requester"); os.IsNotExist(err) {
			os.Mkdir("requester", 0755)
		}

		if _, err := os.Stat("signer"); os.IsNotExist(err) {
			os.Mkdir("signer", 0755)
		}

		if _, err := os.Stat("signature"); os.IsNotExist(err) {
			os.Mkdir("signature", 0755)
		}

		sk, err := signing.NewSecretKey(elliptic.P256())
		if err != nil {
			println("failed to generate secret key")
			return
		}

		sk.Save("signer/signer.secret")

		pk := sk.GetPublicKey()
		pk.Save("requester/signer.public")

		println("Generated keys.")
	}

	if *request {
		println("Generting request...")

		pk, loadError := signing.LoadPublicKey("requester/signer.public")
		if loadError != nil {
			println("failed to load signer public key, try -genkeys first")
			print(loadError.Error())
			return
		}

		compressed, compressError := signing.CompressInfo(elliptic.P256(), []byte(*info))
		if compressError != nil {
			println("failed to compress info")
			return
		}

		requester, requestError := signing.CreateRequester(pk, compressed, []byte(*message))
		if requestError != nil {
			println("failed to create requester")
			return
		}

		requester.Save("requester/request.0")

		println("Generated request.")
	}

	if *stage1 {
		println("Processing, stage 1...")

		sk, loadError := signing.LoadSecretKey("signer/signer.secret")
		if loadError != nil {
			println("failed to load secret, try -genkeys first")
			print(loadError.Error())
			return
		}

		compressed, compressError := signing.CompressInfo(elliptic.P256(), []byte(*info))
		if compressError != nil {
			println("failed to compress info")
			return
		}

		signer, signerError := signing.CreateSigner(*sk, compressed)
		if signerError != nil {
			println("failed to create signer")
			return
		}

		requester, requestError := signing.LoadRequester("requester/request.0")
		if requestError != nil {
			println("failed to load requester")
			println(requestError.Error())
			return
		}

		msg1, messageError := signer.CreateMessage1()
		if messageError != nil {
			println("failed to create msg1")
			return
		}

		processError := requester.ProcessMessage1(msg1)
		if processError != nil {
			println("failed to process msg1")
		}

		requesterSaveError := requester.Save("requester/request.1")
		if requesterSaveError != nil {
			println("failed to save requester")
			return
		}

		signerSaveError := signer.Save("signer/signer.1")
		if signerSaveError != nil {
			println("failed to save signer")
			print(signerSaveError.Error())
			return
		}

		println("Processed.")
	}

	if *stage2 {
		println("Processing, stage 2...")

		signer, signerError := signing.LoadSigner("signer/signer.1")
		if signerError != nil {
			println("failed to create signer")
			println(signerError.Error())
			return
		}

		requester, requestError := signing.LoadRequester("requester/request.1")
		if requestError != nil {
			println("failed to create requester")
			return
		}

		msg2, createError := requester.CreateMessage2()
		if createError != nil {
			println("failed to create msg2")
			return
		}

		processError := signer.ProcessMessage2(msg2)
		if processError != nil {
			println("failed to process msg2")
			println(processError.Error())
			return
		}

		requester.Save("requester/request.2")
		signer.Save("signer/signer.2")

		println("Processed.")
	}

	if *stage3 {
		println("Processing, stage 3...")

		signer, signerError := signing.LoadSigner("signer/signer.2")
		if signerError != nil {
			println("failed to create signer")
			println(signerError.Error())
			return
		}

		requester, requestError := signing.LoadRequester("requester/request.2")
		if requestError != nil {
			println("failed to create requester")
			return
		}

		msg3, createError := signer.CreateMessage3()
		if createError != nil {
			println("failed to create msg3")
			return
		}

		processError := requester.ProcessMessage3(msg3)
		if processError != nil {
			println("failed to process msg3")
			println(processError.Error())
			return
		}

		requester.Save("requester/request.3")
		signer.Save("signer/signer.3")

		println("Processed.")
	}

	if *sign {
		println("Signing...")

		requester, loadError := signing.LoadRequester("requester/request.3")
		if loadError != nil {
			println("failed to load requester, try -request first")
			return
		}

		sig, signError := requester.Signature()
		if signError != nil {
			println("failed to obtain signature")
			print(signError.Error())
			return
		}

		sig.Save("signature/signature")
		println("Signed")
	}

	if *check {
		println("Checking signature...")

		sig, signatureError := signing.LoadSignature("signature/signature")
		if signatureError != nil {
			println("failed to load signature")
			println(signatureError.Error())
			return
		}

		sk, loadError := signing.LoadSecretKey("signer/signer.secret")
		if loadError != nil {
			println("failed to load secret, try -genkeys first")
			print(loadError.Error())
			return
		}

		pk := sk.GetPublicKey()

		compressed, compressError := signing.CompressInfo(elliptic.P256(), []byte(*info))
		if compressError != nil {
			println("failed to compress info")
			return
		}

		if !pk.Check(*sig, compressed, []byte(*message)) {
			println("failed to validate signature")
			println(*info)
			println(*message)
			return
		}

		println("Success!")
	}

	if *server {
		doServer()
	}

	if *client {
		doClient(*info, *message)
	}

	if *demo {
		go doServer()
		doClient(*info, *message)
	}
}

func doClient(info string, message string) {
	pk, loadError := signing.LoadPublicKey("requester/signer.public")
	if loadError != nil {
		println("failed to load signer public key, try -genkeys first")
		print(loadError.Error())
		return
	}

	compressed, compressError := signing.CompressInfo(elliptic.P256(), []byte(info))
	if compressError != nil {
		println("failed to compress info")
		return
	}

	requester, requestError := signing.CreateRequester(pk, compressed, []byte(message))
	if requestError != nil {
		println("failed to create requester")
		return
	}

	connection, dialError := net.Dial("tcp","localhost:1234")
	if dialError != nil {
		println("failure dialing")
		return
	}

	requester = requesterStage1(connection, requester, info)
	requester = requesterStage2(connection, requester)
	requester = requesterStage3(connection, requester)
	signature := requesterSign(requester)

	signature.Save("signature")
	println("Signed")
}

func doServer() {
	sk, loadError := signing.LoadSecretKey("signer/signer.secret")
	if loadError != nil {
		println("failed to load secret, try -genkeys first")
		print(loadError.Error())
		return
	}

	println("Listening...")

	listener, listenError := net.Listen("tcp", "localhost:1234")
	if listenError != nil {
		println("failure to listen on socket")
		println(listenError.Error())
		return
	}

	for {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			return
		}

		println("Incoming connection")
		println(connection.RemoteAddr().String())

		serverHandleConnection(connection, sk)
	}
}

func serverHandleConnection(connection net.Conn, sk *signing.SecretKey) {
	signer := signerStage1(connection, sk)
	if signer == nil {
		println("error in stage 1")
		return
	}

	signer = signerStage2(connection, signer)
	if signer == nil {
		println("error in stage 2")
		return
	}

	signerStage3(connection, signer)
}

func signerStage1(connection net.Conn, sk *signing.SecretKey) *signing.StateSigner {
	info := receiveMessage(connection)

	compressed, compressError := signing.CompressInfo(elliptic.P256(), info)
	if compressError != nil {
		println("failed to compress info")
		return nil
	}

	signer, signerError := signing.CreateSigner(*sk, compressed)
	if signerError != nil {
		println("failed to create signer")
		return nil
	}

	msg1, messageError := signer.CreateMessage1()
	if messageError != nil {
		println("failed to create msg1")
		return nil
	}

	response := msg1.Bytes()
	sendMessage(connection, response)

	return signer
}

func signerStage2(connection net.Conn, signer *signing.StateSigner) *signing.StateSigner {
	msg2Bytes := receiveMessage(connection)

	msg2, messageError := signing.Message2FromBytes(msg2Bytes)
	if messageError != nil {
		return nil
	}

	processError := signer.ProcessMessage2(*msg2)
	if processError != nil {
		println("failed to process msg2Bytes")
		println(processError.Error())
		return nil
	}

	return signer
}

func signerStage3(connection net.Conn, signer *signing.StateSigner) {
	msg3, createError := signer.CreateMessage3()
	if createError != nil {
		println("failed to create msg3")
		return
	}

	response := msg3.Bytes()
	sendMessage(connection, response)
}

func requesterStage1(connection net.Conn, requester *signing.StateRequester, info string) *signing.StateRequester {
	sendMessage(connection, []byte(info))

	msg1Bytes := receiveMessage(connection)

	msg1, messageError := signing.Message1FromBytes(msg1Bytes)
	if messageError != nil {
		return nil
	}

	processError := requester.ProcessMessage1(*msg1)
	if processError != nil {
		println("failed to process msg1")
	}

	return requester
}

func requesterStage2(connection net.Conn, requester *signing.StateRequester) *signing.StateRequester {
	msg2, createError := requester.CreateMessage2()
	if createError != nil {
		println("failed to create msg2")
		return nil
	}

	response := msg2.Bytes()
	sendMessage(connection, response)

	return requester
}

func requesterStage3(connection net.Conn, requester *signing.StateRequester) *signing.StateRequester {
	msg3Bytes := receiveMessage(connection)

	msg3, messageError := signing.Message3FromBytes(msg3Bytes)
	if messageError != nil {
		return nil
	}

	processError := requester.ProcessMessage3(*msg3)
	if processError != nil {
		println("failed to process msg3")
		println(processError.Error())
		return nil
	}

	return requester
}

func requesterSign(requester *signing.StateRequester) *signing.Signature {
	sig, signError := requester.Signature()
	if signError != nil {
		println("failed to obtain signature")
		print(signError.Error())
		return nil
	}

	return &sig
}

func sendMessage(connection net.Conn, data []byte) {
	length := int64(len(data))

	lengthBytes := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(lengthBytes, length)

	connection.Write(lengthBytes)
	connection.Write(data)
}

func receiveMessage(connection net.Conn) []byte {
	lengthBytes := make([]byte, binary.MaxVarintLen64)
	connection.Read(lengthBytes)

	length, _ := binary.Varint(lengthBytes)

	data := make([]byte, length)
	connection.Read(data)

	return data
}