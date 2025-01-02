package main

import (
	"flag"
	"fmt"
	"math"
	"mk-lr/mkckks"
	"mk-lr/mkrlwe"
	"os"
	"path"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func printDebug(ciphertexts *mkckks.Ciphertext, v []complex128) {

	fmt.Println()
	fmt.Printf("Level: %d \n", ciphertexts.Level())
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertexts.Scale))
	fmt.Printf("decrypted Values: %6.10f %6.10f %6.10f %6.10f %6.10f...\n", v[0], v[1], v[2], v[3], v[4])
	fmt.Println()
}

var keyPath string = "/data/workspace/go_projects/share2gain/mk_client_demo"
var resultPath string = "/data/workspace/go_projects/share2gain/mk_server_demo"

func showClientData(client string) {
	paramsFile := path.Join(keyPath, "ckks_params.dat")

	skFile := path.Join(keyPath, client+"_ckks_seckey.dat")

	cipherDataFile := path.Join(keyPath, client+"_ckks_cipher_data.dat")

	if !fileExists(paramsFile) {
		fmt.Printf("%s does not exist", paramsFile)
		return
	}

	if !fileExists(skFile) {
		fmt.Printf("%s does not exist", skFile)
		return
	}

	if !fileExists(cipherDataFile) {
		fmt.Printf("%s does not exist", cipherDataFile)
		return
	}

	//读取并反序列化公共安全参数
	var params mkckks.Parameters
	paramsBytes, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}
	params.UnmarshalBinary(paramsBytes)

	var sk mkrlwe.SecretKey

	skBytes, err := os.ReadFile(skFile)
	if err != nil {
		panic(err)
	}

	sk.UnmarshalBinary(skBytes)

	var skSet mkrlwe.SecretKeySet
	skSet.Value = make(map[string]*mkrlwe.SecretKey)

	skSet.Value[client] = &sk

	var ciphertexts mkckks.Ciphertext

	cipherBytes, err := os.ReadFile(cipherDataFile)
	if err != nil {
		panic(err)
	}

	ciphertexts.UnmarshalBinary(cipherBytes)

	decryptor := mkckks.NewDecryptor(params)

	msgOut := decryptor.Decrypt(&ciphertexts, &skSet)

	fmt.Printf("%s decrypted data:", client)
	fmt.Println()

	printDebug(&ciphertexts, msgOut.Value)

}

func eval(client_1 string, client_2 string) {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from", r)
		}
	}()

	paramsFile := path.Join(keyPath, "ckks_params.dat")

	skFile_1 := path.Join(keyPath, client_1+"_ckks_seckey.dat")
	skFile_2 := path.Join(keyPath, client_2+"_ckks_seckey.dat")

	cryptSumFile := path.Join(resultPath, "sum_ckks_data.dat")
	cryptSubFile := path.Join(resultPath, "sub_ckks_data.dat")
	cryptMulFile := path.Join(resultPath, "mul_ckks_data.dat")
	cryptAllSumFile := path.Join(resultPath, "all_sum_ckks_data.dat")
	cryptAllMulFile := path.Join(resultPath, "all_mul_ckks_data.dat")

	cryptRotateFile := path.Join(resultPath, "rotate_ckks_data.dat")

	if !fileExists(paramsFile) {
		fmt.Printf("%s does not exist", paramsFile)
		return
	}

	if !fileExists(skFile_1) {
		fmt.Printf("%s does not exist", skFile_1)
		return
	}

	if !fileExists(skFile_2) {
		fmt.Printf("%s does not exist", skFile_2)
		return
	}

	if !fileExists(cryptSumFile) {
		fmt.Printf("%s does not exist", cryptSumFile)
		return
	}

	if !fileExists(cryptSubFile) {
		fmt.Printf("%s does not exist", cryptSubFile)
		return
	}

	if !fileExists(cryptMulFile) {
		fmt.Printf("%s does not exist", cryptMulFile)
		return
	}

	if !fileExists(cryptAllSumFile) {
		fmt.Printf("%s does not exist", cryptSubFile)
		return
	}

	if !fileExists(cryptAllMulFile) {
		fmt.Printf("%s does not exist", cryptMulFile)
		return
	}

	if !fileExists(cryptRotateFile) {
		fmt.Printf("%s does not exist", cryptMulFile)
		return
	}

	//读取并反序列化公共安全参数
	var params mkckks.Parameters
	paramsBytes, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}
	params.UnmarshalBinary(paramsBytes)

	//读取双方私钥并构建联合私钥用于解密
	var sk1 mkrlwe.SecretKey
	var sk2 mkrlwe.SecretKey

	skBytes, err := os.ReadFile(skFile_1)
	if err != nil {
		panic(err)
	}

	sk1.UnmarshalBinary(skBytes)

	skBytes, err = os.ReadFile(skFile_2)
	if err != nil {
		panic(err)
	}

	sk2.UnmarshalBinary(skBytes)

	var skSet mkrlwe.SecretKeySet
	skSet.Value = make(map[string]*mkrlwe.SecretKey)

	skSet.Value[client_1] = &sk1
	skSet.Value[client_2] = &sk2

	//从文件读取5个密文
	var ctSum mkckks.Ciphertext
	var ctSub mkckks.Ciphertext
	var ctMul mkckks.Ciphertext
	var ctAllSum mkckks.Ciphertext
	var ctAllMul mkckks.Ciphertext
	var ctRot mkckks.Ciphertext

	cipherBytes, err := os.ReadFile(cryptSumFile)
	if err != nil {
		panic(err)
	}

	ctSum.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptSubFile)
	if err != nil {
		panic(err)
	}

	ctSub.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptMulFile)
	if err != nil {
		panic(err)
	}

	ctMul.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptAllSumFile)
	if err != nil {
		panic(err)
	}

	ctAllSum.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptAllMulFile)
	if err != nil {
		panic(err)
	}

	ctAllMul.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptRotateFile)
	if err != nil {
		panic(err)
	}

	ctRot.UnmarshalBinary(cipherBytes)

	decryptor := mkckks.NewDecryptor(params)

	msgSum := decryptor.Decrypt(&ctSum, &skSet)
	fmt.Printf("%s and %s decrypted sum:", client_1, client_2)
	fmt.Println()
	printDebug(&ctSum, msgSum.Value)

	msgSub := decryptor.Decrypt(&ctSub, &skSet)
	fmt.Printf("%s and %s decrypted sub:", client_1, client_2)
	fmt.Println()
	printDebug(&ctSub, msgSub.Value)

	msgMul := decryptor.Decrypt(&ctMul, &skSet)
	fmt.Printf("%s and %s decrypted multiply:", client_1, client_2)
	fmt.Println()
	printDebug(&ctMul, msgMul.Value)

	msgAllSum := decryptor.Decrypt(&ctAllSum, &skSet)
	fmt.Printf("%s and %s decrypted all sum:", client_1, client_2)
	fmt.Println()
	printDebug(&ctMul, msgAllSum.Value)

	msgAllMul := decryptor.Decrypt(&ctAllMul, &skSet)
	fmt.Printf("%s and %s decrypted all multiply:", client_1, client_2)
	fmt.Println()
	printDebug(&ctMul, msgAllMul.Value)

	msgRotate := decryptor.Decrypt(&ctRot, &skSet)
	fmt.Printf("%s and %s decrypted rotate:", client_1, client_2)
	fmt.Println()
	printDebug(&ctRot, msgRotate.Value)

	//演示只有双方任意一个私钥无法解密它们的运算结果, 会抛出异常
	var skSetSingle mkrlwe.SecretKeySet
	skSetSingle.Value = make(map[string]*mkrlwe.SecretKey)

	skSetSingle.Value[client_1] = &sk1

	fmt.Println("try to decrypt sum with one party sk")
	msgSum = decryptor.Decrypt(&ctSum, &skSetSingle)
	fmt.Printf("%s and %s decrypted sum:", client_1, client_2)
	fmt.Println()
	printDebug(&ctSum, msgSum.Value)

}

func main() {
	client_1 := flag.String("client_1", "company_a", "company name to do ckks encrytion")
	client_2 := flag.String("client_2", "company_b", "company name to do ckks encrytion")

	flag.Parse()

	showClientData(*client_1)

	showClientData(*client_2)

	eval(*client_1, *client_2)
}
