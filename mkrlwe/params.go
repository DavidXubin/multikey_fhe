package mkrlwe

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

type Parameters struct {
	rlwe.Parameters
	CRS   map[int]*SwitchingKey
	gamma int
}

// NewParameters takes rlwe Parameter as input, generate two CRSs
// and then return mkrlwe parameter
func NewParameters(params rlwe.Parameters, gamma int) Parameters {
	ret := new(Parameters)
	ret.Parameters = params
	ret.gamma = gamma

	ringQP := params.RingQP()
	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1

	alpha := params.PCount() / gamma
	beta := int(math.Ceil(float64(params.QCount()) / float64(alpha)))

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	uniformSamplerQ := ring.NewUniformSampler(prng, params.RingQ())
	uniformSamplerP := ring.NewUniformSampler(prng, params.RingP())

	ret.CRS = make(map[int]*SwitchingKey)

	idxs := []int{
		0, -1, //CRS for relin key
		-2,     //CRS for conj key
		-3, -4, //CRS for BFV relin key
	}

	// CRS for rot keys
	for i := 0; i < params.LogN()-1; i++ {
		idxs = append(idxs, 1<<i)
	}

	// generate CRS for default indexes
	for _, idx := range idxs {
		ret.CRS[idx] = new(SwitchingKey)
		ret.CRS[idx].Value = make([]rlwe.PolyQP, beta)
		for i := 0; i < beta; i++ {
			ret.CRS[idx].Value[i] = ringQP.NewPoly()
			uniformSamplerQ.Read(ret.CRS[idx].Value[i].Q)
			uniformSamplerP.Read(ret.CRS[idx].Value[i].P)
			ringQP.MFormLvl(levelQ, levelP, ret.CRS[idx].Value[i], ret.CRS[idx].Value[i])
		}
	}

	return *ret
}

func (params Parameters) Alpha() int {
	return params.PCount() / params.gamma
}

func (params Parameters) Beta(levelQ int) int {
	alpha := params.Alpha()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))
	return beta
}

func (params Parameters) Gamma() int {
	return params.gamma
}

func (params *Parameters) AddCRS(idx int) {

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	uniformSamplerQ := ring.NewUniformSampler(prng, params.RingQ())
	uniformSamplerP := ring.NewUniformSampler(prng, params.RingP())

	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1

	beta := params.Beta(params.MaxLevel())
	params.CRS[idx] = new(SwitchingKey)
	params.CRS[idx].Value = make([]rlwe.PolyQP, beta)

	for i := 0; i < beta; i++ {
		params.CRS[idx].Value[i] = params.RingQP().NewPoly()
		uniformSamplerQ.Read(params.CRS[idx].Value[i].Q)
		uniformSamplerP.Read(params.CRS[idx].Value[i].P)
		params.RingQP().MFormLvl(levelQ, levelP, params.CRS[idx].Value[i], params.CRS[idx].Value[i])
	}
}

func (params Parameters) GetDataLen(WithMetaData bool) (dataLen int) {

	if WithMetaData {
		dataLen = 4
	}

	dataLen += params.Parameters.MarshalBinarySize()

	for _, k := range params.CRS {
		if WithMetaData {
			dataLen += 4
		}
		dataLen += k.GetDataLen(WithMetaData)
	}

	dataLen += 4
	return
}

func (params Parameters) MarshalBinary() ([]byte, error) {

	var pointer = 0
	var rlweParamsBuf []byte
	var err error

	data := make([]byte, params.GetDataLen(true))

	if rlweParamsBuf, err = params.Parameters.MarshalBinary(); err != nil {
		return []byte{}, err
	}

	binary.BigEndian.PutUint32(data[pointer:pointer+4], uint32(len(rlweParamsBuf)))

	pointer += 4

	copy(data[pointer:], rlweParamsBuf)

	pointer += len(rlweParamsBuf)

	for idx, key := range params.CRS {

		binary.BigEndian.PutUint32(data[pointer:pointer+4], uint32(idx))

		pointer += 4

		if pointer, err = key.encode(pointer, data); err != nil {
			return nil, err
		}

	}

	binary.BigEndian.PutUint32(data[pointer:pointer+4], uint32(params.gamma))

	return data, nil
}

func (p *Parameters) UnmarshalBinary(data []byte) error {
	if len(data) < 11 {
		return fmt.Errorf("invalid rlwe.Parameter serialization")
	}

	var pointer = 4
	var err error
	var inc = 0

	rlweParamsLen := int(binary.BigEndian.Uint32(data))

	var ckksParams rlwe.Parameters

	ckksParams.UnmarshalBinary(data[pointer : pointer+rlweParamsLen])

	p.Parameters = ckksParams

	pointer += rlweParamsLen

	p.CRS = make(map[int]*SwitchingKey)

	for pointer < len(data)-4 {

		idx := int32(binary.BigEndian.Uint32(data[pointer:]))
		pointer += 4

		swk := new(SwitchingKey)

		if inc, err = swk.decode(data[pointer:]); err != nil {
			return err
		}

		pointer += inc

		p.CRS[int(idx)] = swk
	}

	p.gamma = int(int32(binary.BigEndian.Uint32(data[pointer:])))

	return err
}
