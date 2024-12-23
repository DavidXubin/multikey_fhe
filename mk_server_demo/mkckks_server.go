package main

import (
	"flag"
	"fmt"
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

var dataPath string = "/data/workspace/go_projects/share2gain/mk_client_demo"

func calulation(client_1 string, client_2 string) {
	paramsFile := path.Join(dataPath, "ckks_params.dat")

	pubFile_1 := path.Join(dataPath, client_1+"_ckks_pubkey.dat")
	rlkFile_1 := path.Join(dataPath, client_1+"_ckks_rlkey.dat")
	rtkFile_1 := path.Join(dataPath, client_1+"_ckks_rtkey.dat")
	cryptDataFile_1 := path.Join(dataPath, client_1+"_ckks_cipher_data.dat")

	pubFile_2 := path.Join(dataPath, client_2+"_ckks_pubkey.dat")
	rlkFile_2 := path.Join(dataPath, client_2+"_ckks_rlkey.dat")
	rtkFile_2 := path.Join(dataPath, client_2+"_ckks_rtkey.dat")
	cryptDataFile_2 := path.Join(dataPath, client_2+"_ckks_cipher_data.dat")

	if !fileExists(paramsFile) {
		fmt.Printf("%s does not exist", paramsFile)
		return
	}

	if !fileExists(pubFile_1) {
		fmt.Printf("%s does not exist", pubFile_1)
		return
	}

	if !fileExists(rlkFile_1) {
		fmt.Printf("%s does not exist", rlkFile_1)
		return
	}

	if !fileExists(rtkFile_1) {
		fmt.Printf("%s does not exist", rtkFile_1)
		return
	}

	if !fileExists(cryptDataFile_1) {
		fmt.Printf("%s does not exist", cryptDataFile_1)
		return
	}

	if !fileExists(pubFile_2) {
		fmt.Printf("%s does not exist", pubFile_1)
		return
	}

	if !fileExists(rlkFile_2) {
		fmt.Printf("%s does not exist", rlkFile_1)
		return
	}

	if !fileExists(rtkFile_2) {
		fmt.Printf("%s does not exist", rtkFile_2)
		return
	}

	if !fileExists(cryptDataFile_2) {
		fmt.Printf("%s does not exist", cryptDataFile_1)
		return
	}

	//读取并反序列化公共安全参数
	var params mkckks.Parameters
	paramsBytes, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}
	params.UnmarshalBinary(paramsBytes)

	//读取并反序列化双方的再线性化参数
	var rlkBytes []byte
	var rlk_1 mkrlwe.RelinearizationKey
	var rlk_2 mkrlwe.RelinearizationKey

	rlkBytes, err = os.ReadFile(rlkFile_1)
	if err != nil {
		panic(err)
	}
	rlk_1.UnmarshalBinary(rlkBytes)

	rlkBytes, err = os.ReadFile(rlkFile_2)
	if err != nil {
		panic(err)
	}
	rlk_2.UnmarshalBinary(rlkBytes)

	//使用双方的再线性化密钥构建一个联合再线性密钥集
	rlkSet := mkrlwe.NewRelinearizationKeyKeySet(params.Parameters)
	rlkSet.AddRelinearizationKey(&rlk_1)
	rlkSet.AddRelinearizationKey(&rlk_2)

	//读取并反序列化双方的旋转密钥
	var rtkBytes []byte
	var rtkset_1 mkrlwe.RotationKeySet
	var rtkset_2 mkrlwe.RotationKeySet

	rtkBytes, err = os.ReadFile(rtkFile_1)
	if err != nil {
		panic(err)
	}
	rtkset_1.UnmarshalBinary(rtkBytes)

	rtkBytes, err = os.ReadFile(rtkFile_2)
	if err != nil {
		panic(err)
	}
	rtkset_2.UnmarshalBinary(rtkBytes)

	rtkSet := mkrlwe.NewRotationKeySet()
	rtkSet.Value[client_1] = rtkset_1.Value[client_1]
	rtkSet.Value[client_2] = rtkset_2.Value[client_2]

	//使用公共参数构建评估器
	evaluator := mkckks.NewEvaluator(params)

	//读取并反序列化双方的密文
	var ct1 mkckks.Ciphertext
	var ct2 mkckks.Ciphertext

	cipherBytes, err := os.ReadFile(cryptDataFile_1)
	if err != nil {
		panic(err)
	}

	ct1.UnmarshalBinary(cipherBytes)

	cipherBytes, err = os.ReadFile(cryptDataFile_2)
	if err != nil {
		panic(err)
	}

	ct2.UnmarshalBinary(cipherBytes)

	//对双方密文数组求和，对应位置上密文相加
	ctAdd := evaluator.AddNew(&ct1, &ct2)

	//对双方密文数组求差，对应位置相加密文相减
	ctSub := evaluator.SubNew(&ct1, &ct2)

	//对双方密文数组求积，对应位置相加密文相乘
	ctMul := evaluator.MulRelinNew(&ct1, &ct2, rlkSet)

	fmt.Print("Start to add and multiply all data")

	//求密文的累加t
	ctSum := ctAdd.CopyNew()
	for i := 1; i <= 32; i *= 2 {
		ctrot := evaluator.RotateNew(ctSum, i, rtkSet)
		ctSum = evaluator.AddNew(ctSum, ctrot)
	}

	//求密文的累乘
	ctAllMult := ctMul.CopyNew()
	for i := 1; i <= 32; i *= 2 {
		ctrot := evaluator.RotateNew(ctAllMult, i, rtkSet)
		ctAllMult = evaluator.MulRelinNew(ctAllMult, ctrot, rlkSet)
	}

	//将双方密文加减乘的3个运算结果分别保存进文件
	sumFile := "sum_ckks_data.dat"
	subFile := "sub_ckks_data.dat"
	mulFile := "mul_ckks_data.dat"
	allSumFile := "all_sum_ckks_data.dat"
	allMulFule := "all_mul_ckks_data.dat"

	cipherBytes, err = ctAdd.MarshalBinary()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(sumFile, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

	cipherBytes, err = ctSub.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(subFile, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

	cipherBytes, err = ctMul.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(mulFile, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

	cipherBytes, err = ctSum.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(allSumFile, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

	cipherBytes, err = ctAllMult.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(allMulFule, cipherBytes, 0640)
	if err != nil {
		panic(err)
	}

}

func main() {
	client_1 := flag.String("client_1", "company_a", "company name to do ckks encrytion")
	client_2 := flag.String("client_2", "company_b", "company name to do ckks encrytion")

	flag.Parse()

	calulation(*client_1, *client_2)
}
