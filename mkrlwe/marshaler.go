package mkrlwe

import (
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
)

// GetDataLen returns the length in bytes of the target SecretKey.
func (sk *SecretKey) GetDataLen(WithMetadata bool) (dataLen int) {
	return sk.Value.GetDataLen(WithMetadata)
}

// MarshalBinary encodes a secret key in a byte slice.
func (sk *SecretKey) MarshalBinary() (data []byte, err error) {

	var pt = 0
	data = make([]byte, sk.GetDataLen(true)+len(sk.ID))
	if pt, err = sk.Value.WriteTo(data); err != nil {
		return nil, err
	}

	copy(data[pt:], []byte(sk.ID))
	return
}

// UnmarshalBinary decodes a previously marshaled SecretKey in the target SecretKey.
func (sk *SecretKey) UnmarshalBinary(data []byte) (err error) {
	var pt = 0
	if pt, err = sk.Value.DecodePolyNew(data); err != nil {
		return err
	}

	sk.ID = string(data[pt:])
	return
}

// GetDataLen returns the length in bytes of the target PublicKey.
func (pk *PublicKey) GetDataLen(WithMetadata bool) (dataLen int) {
	return pk.Value[0].GetDataLen(WithMetadata) + pk.Value[1].GetDataLen(WithMetadata)
}

// MarshalBinary encodes a PublicKey in a byte slice.
func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	data = make([]byte, pk.GetDataLen(true)+len(pk.ID))
	var inc, pt int
	if inc, err = pk.Value[0].WriteTo(data[pt:]); err != nil {
		return nil, err
	}
	pt += inc

	if inc, err = pk.Value[1].WriteTo(data[pt:]); err != nil {
		return nil, err
	}

	pt += inc

	copy(data[pt:], []byte(pk.ID))

	return
}

// UnmarshalBinary decodes a previously marshaled PublicKey in the target PublicKey.
func (pk *PublicKey) UnmarshalBinary(data []byte) (err error) {

	var pt, inc int
	if inc, err = pk.Value[0].DecodePolyNew(data[pt:]); err != nil {
		return
	}
	pt += inc

	if inc, err = pk.Value[1].DecodePolyNew(data[pt:]); err != nil {
		return
	}
	pt += inc

	pk.ID = string(data[pt:])

	return
}

// GetDataLen returns the length in bytes of the target EvaluationKey.
func (rlk *RelinearizationKey) GetDataLen(WithMetadata bool) (dataLen int) {

	if WithMetadata {
		dataLen++
	}

	for _, evakey := range rlk.Value {
		dataLen += (*SwitchingKey)(evakey).GetDataLen(WithMetadata)
	}

	return
}

// MarshalBinary encodes an EvaluationKey key in a byte slice.
func (rlk *RelinearizationKey) MarshalBinary() (data []byte, err error) {

	var pointer int

	dataLen := rlk.GetDataLen(true)

	data = make([]byte, dataLen+len(rlk.ID))

	data[0] = uint8(len(rlk.Value))

	pointer++

	for _, evakey := range rlk.Value {

		if pointer, err = (*SwitchingKey)(evakey).encode(pointer, data); err != nil {
			return nil, err
		}
	}

	copy(data[pointer:], []byte(rlk.ID))

	return data, nil
}

// UnmarshalBinary decodes a previously marshaled EvaluationKey in the target EvaluationKey.
func (rlk *RelinearizationKey) UnmarshalBinary(data []byte) (err error) {

	deg := int(data[0])

	//rlk.Value = make([]*SwitchingKey, deg)

	pointer := 1
	var inc int
	for i := 0; i < deg; i++ {
		rlk.Value[i] = new(SwitchingKey)
		if inc, err = rlk.Value[i].decode(data[pointer:]); err != nil {
			return err
		}
		pointer += inc
	}

	rlk.ID = string(data[pointer:])

	return nil
}

// GetDataLen returns the length in bytes of the target SwitchingKey.
func (swk *SwitchingKey) GetDataLen(WithMetadata bool) (dataLen int) {

	if WithMetadata {
		dataLen++
	}

	for j := uint64(0); j < uint64(len(swk.Value)); j++ {
		dataLen += swk.Value[j].GetDataLen(WithMetadata)
	}

	return
}

// MarshalBinary encodes an SwitchingKey in a byte slice.
func (swk *SwitchingKey) MarshalBinary() (data []byte, err error) {

	data = make([]byte, swk.GetDataLen(true))

	if _, err = swk.encode(0, data); err != nil {
		return nil, err
	}

	return data, nil
}

// UnmarshalBinary decode a previously marshaled SwitchingKey in the target SwitchingKey.
func (swk *SwitchingKey) UnmarshalBinary(data []byte) (err error) {

	if _, err = swk.decode(data); err != nil {
		return err
	}

	return nil
}

func (swk *SwitchingKey) encode(pointer int, data []byte) (int, error) {

	var err error
	var inc int

	data[pointer] = uint8(len(swk.Value))

	pointer++

	for j := 0; j < len(swk.Value); j++ {

		if inc, err = swk.Value[j].WriteTo(data[pointer : pointer+swk.Value[j].GetDataLen(true)]); err != nil {
			return pointer, err
		}

		pointer += inc
	}

	return pointer, nil
}

func (swk *SwitchingKey) decode(data []byte) (pointer int, err error) {

	decomposition := int(data[0])

	pointer = 1

	swk.Value = make([]rlwe.PolyQP, decomposition)

	var inc int

	for j := 0; j < decomposition; j++ {

		swk.Value[j].Q = new(ring.Poly)
		if inc, err = swk.Value[j].DecodePolyNew(data[pointer:]); err != nil {
			return
		}
		pointer += inc

	}

	return
}
