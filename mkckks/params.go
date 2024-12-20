package mkckks

import (
	"encoding/binary"
	"fmt"
	"math"
	"mk-lr/mkrlwe"

	"github.com/ldsec/lattigo/v2/ckks"
)

// Parameters represents a parameter set for the CKKS cryptosystem. Its fields are private and
// immutable. See ParametersLiteral for user-specified parameters.
type Parameters struct {
	mkrlwe.Parameters

	logSlots int
	scale    float64
}

// NewParameters instantiate a set of MKCKKS parameters from the generic CKKS parameters and the CKKS-specific ones.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
func NewParameters(ckksParams ckks.Parameters) Parameters {

	ret := new(Parameters)
	ret.Parameters = mkrlwe.NewParameters(ckksParams.Parameters, 2)
	ret.logSlots = ckksParams.LogSlots()
	ret.scale = ckksParams.Scale()

	return *ret
}

// Scale returns the default plaintext/ciphertext scale
func (p Parameters) Scale() float64 {
	return p.scale
}

// Slots returns number of available plaintext slots
func (p Parameters) Slots() int {
	return 1 << p.logSlots
}

// LogSlots returns the log of the number of slots
func (p Parameters) LogSlots() int {
	return p.logSlots
}

func (params Parameters) GetDataLen(WithMetaData bool) (dataLen int) {

	if WithMetaData {
		dataLen = 12
	}

	dataLen += params.Parameters.GetDataLen(true)

	return
}

func (params Parameters) MarshalBinary() ([]byte, error) {

	var pointer = 0
	var mkrlweParamsBuf []byte
	var err error

	data := make([]byte, params.GetDataLen(true))

	binary.BigEndian.PutUint32(data[pointer:pointer+4], uint32(params.logSlots))

	binary.BigEndian.PutUint64(data[pointer+4:pointer+12], math.Float64bits(params.scale))

	pointer += 12

	if mkrlweParamsBuf, err = params.Parameters.MarshalBinary(); err != nil {
		return []byte{}, err
	}

	copy(data[pointer:], mkrlweParamsBuf)

	return data, nil
}

func (p *Parameters) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("invalid rlwe.Parameter serialization")
	}

	var pointer = 0
	var err error

	p.logSlots = int(binary.BigEndian.Uint32(data))

	pointer += 4
	p.scale = math.Float64frombits(binary.BigEndian.Uint64(data[pointer:]))

	if err = p.Parameters.UnmarshalBinary(data[pointer+8:]); err != nil {
		return err
	}

	return err
}
