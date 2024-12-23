package main

import (
	"flag"
	"fmt"
	"math"
	"os"

	"mk-lr/mkckks"
	"mk-lr/mkrlwe"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

var PN15QP880 = ckks.ParametersLiteral{
	LogN:     15,
	LogSlots: 14,
	//60 + 13x54
	Q: []uint64{
		0xfffffffff6a0001,

		0x3fffffffd60001, 0x3fffffffca0001,
		0x3fffffff6d0001, 0x3fffffff5d0001,
		0x3fffffff550001, 0x3fffffff390001,
		0x3fffffff360001, 0x3fffffff2a0001,
		0x3fffffff000001, 0x3ffffffefa0001,
		0x3ffffffef40001, 0x3ffffffed70001,
		0x3ffffffed30001,
	},
	P: []uint64{
		//59 x 2
		0x7ffffffffe70001, 0x7ffffffffe10001,
	},
	Scale: 1 << 54,
	Sigma: rlwe.DefaultSigma,
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func printDebug(ciphertexts *mkckks.Ciphertext, valuesTest []complex128) {

	fmt.Println()
	fmt.Printf("Level: %d \n", ciphertexts.Level())
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertexts.Scale))
	fmt.Printf("decrypted Values: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Println()
}

func decryptTest(clientName string) {

	paramsFile := "ckks_params.dat"
	secFile := clientName + "_ckks_seckey.dat"
	cipherDataFile := clientName + "_ckks_cipher_data.dat"

	if !fileExists(paramsFile) {
		fmt.Printf("%s does not exist", paramsFile)
		return
	}

	if !fileExists(secFile) {
		fmt.Printf("%s does not exist", secFile)
		return
	}

	if !fileExists(cipherDataFile) {
		fmt.Printf("%s does not exist", cipherDataFile)
		return
	}

	var params mkckks.Parameters
	paramsBytes, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}
	params.UnmarshalBinary(paramsBytes)

	var sk mkrlwe.SecretKey

	skBytes, err := os.ReadFile(secFile)
	if err != nil {
		panic(err)
	}

	sk.UnmarshalBinary(skBytes)

	var skSet mkrlwe.SecretKeySet
	skSet.Value = make(map[string]*mkrlwe.SecretKey)

	skSet.Value[clientName] = &sk

	var ciphertexts mkckks.Ciphertext

	cipherBytes, err := os.ReadFile(cipherDataFile)
	if err != nil {
		panic(err)
	}

	ciphertexts.UnmarshalBinary(cipherBytes)

	decryptor := mkckks.NewDecryptor(params)

	msgOut := decryptor.Decrypt(&ciphertexts, &skSet)

	printDebug(&ciphertexts, msgOut.Value)

}

func mkgenerate(clientName string) {

	var err error
	sampleNum := 5

	paramsFile := "ckks_params.dat"
	pubFile := clientName + "_ckks_pubkey.dat"
	secFile := clientName + "_ckks_seckey.dat"
	rlkFile := clientName + "_ckks_rlkey.dat"
	rtkFile := clientName + "_ckks_rtkey.dat"

	// This example packs random 8192 float64 values in the range [-8, 8]
	// and approximates the function 1/(exp(-x) + 1) over the range [-8, 8].
	// The result is then parsed and compared to the expected result.

	// Scheme params are taken directly from the proposed defaults
	var params mkckks.Parameters

	if fileExists(paramsFile) {
		paramsBytes, err := os.ReadFile(paramsFile)
		if err != nil {
			panic(err)
		}
		params.UnmarshalBinary(paramsBytes)
	} else {

		ckksParams, err := ckks.NewParametersFromLiteral(PN15QP880)

		if err != nil {
			panic(err)
		}

		params = mkckks.NewParameters(ckksParams)

		paramsBytes, err := params.MarshalBinary()
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(paramsFile, paramsBytes, 0640)
		if err != nil {
			panic(err)
		}
	}

	// Keys
	kgen := mkckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair(clientName)

	//辅助密钥，用于多密钥同态乘法中的再线性化
	r := kgen.GenSecretKey(clientName)

	// Relinearization key
	rlk := kgen.GenRelinearizationKey(sk, r)

	//生成旋转密钥
	rtkSet := mkrlwe.NewRotationKeySet()

	kgen.GenDefaultRotationKeys(sk, rtkSet)

	//serialize pub key
	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(pubFile, pubBytes, 0640)
	if err != nil {
		panic(err)
	}

	//serialize sec key
	secBytes, err := sk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(secFile, secBytes, 0640)
	if err != nil {
		panic(err)
	}

	//serialize rlk key
	rlkBytes, err := rlk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(rlkFile, rlkBytes, 0640)
	if err != nil {
		panic(err)
	}

	//serialize rotation keyset
	rtkBytes, err := rtkSet.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(rtkFile, rtkBytes, 0640)
	if err != nil {
		panic(err)
	}

	msg := mkckks.NewMessage(params)

	for i := 0; i < 1<<params.LogSlots(); i++ {
		msg.Value[i] = complex(0, 0)
	}

	for i := 0; i < sampleNum; i++ {
		msg.Value[i] = complex(utils.RandFloat64(-8, 8), 0)
	}

	fmt.Printf("generate values: %6.10f %6.10f %6.10f %6.10f...\n", msg.Value[0], msg.Value[1], msg.Value[2], msg.Value[3])

	encryptor := mkckks.NewEncryptor(params)

	ciphertexts := encryptor.EncryptMsgNew(msg, pk)

	cipherDataFile := clientName + "_ckks_cipher_data.dat"

	cipherBytes, err := ciphertexts.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(cipherDataFile, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

}

func main() {
	client := flag.String("client", "default_company", "company name to do ckks encrytion")

	flag.Parse()

	mkgenerate(*client)

	decryptTest(*client)
}
