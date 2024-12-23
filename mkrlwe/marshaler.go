package mkrlwe

import (
	"encoding/binary"

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

// GetDataLen returns the length in bytes of the target SwitchingKey.
func (rtk *RotationKey) GetDataLen(WithMetadata bool) (dataLen int) {

	dataLen = rtk.Value.GetDataLen(WithMetadata)

	if WithMetadata {
		dataLen++
	}

	dataLen += len(rtk.ID)
	dataLen += 8
	return
}

func (rtk *RotationKey) encode(pointer int, data []byte) (int, error) {

	var err error

	data[pointer] = uint8(len(rtk.ID))
	pointer++

	copy(data[pointer:], []byte(rtk.ID))
	pointer += len(rtk.ID)

	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(rtk.RotIdx))
	pointer += 8

	if pointer, err = rtk.Value.encode(pointer, data); err != nil {
		return pointer, err
	}

	return pointer, nil
}

func (rtk *RotationKey) decode(data []byte) (pointer int, err error) {

	idLen := int(data[0])
	pointer = 1

	rtk.ID = string(data[pointer : pointer+idLen])
	pointer += idLen

	rtk.RotIdx = uint(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8

	rtk.Value = new(SwitchingKey)

	var inc int

	if inc, err = rtk.Value.decode(data[pointer:]); err != nil {
		return
	}

	pointer += inc

	return
}

// GetDataLen returns the length in bytes of the target RotationKeys.
func (rtks *RotationKeySet) GetDataLen(WithMetaData bool) (dataLen int) {
	for ID, rtk := range rtks.Value {
		if WithMetaData {
			//存放id的长度
			dataLen += 1
		}

		dataLen += len(ID)

		//存放map[uint]的数量
		dataLen += 8

		for _, k := range rtk {
			if WithMetaData {
				dataLen += 8
			}
			dataLen += k.GetDataLen(WithMetaData)
		}
	}
	return
}

// MarshalBinary encodes a RotationKeys struct in a byte slice.
func (rtks *RotationKeySet) MarshalBinary() (data []byte, err error) {

	data = make([]byte, rtks.GetDataLen(true))

	pointer := int(0)

	for ID, rtk := range rtks.Value {
		data[pointer] = uint8(len(ID))
		pointer += 1

		copy(data[pointer:], []byte(ID))
		pointer += len(ID)

		binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(len(rtk)))
		pointer += 8

		for idx, key := range rtk {

			binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(idx))
			pointer += 8

			if pointer, err = key.encode(pointer, data); err != nil {
				return nil, err
			}
		}
	}

	return data, nil
}

// UnmarshalBinary decodes a previously marshaled RotationKeys in the target RotationKeys.
func (rtks *RotationKeySet) UnmarshalBinary(data []byte) (err error) {

	var pointer = 0
	rtks.Value = make(map[string]map[uint]*RotationKey)

	for pointer < len(data) {
		idLen := int(data[pointer])
		pointer++

		ID := string(data[pointer : pointer+idLen])
		pointer += idLen

		rtks.Value[ID] = make(map[uint]*RotationKey)

		keyLen := uint(binary.BigEndian.Uint64(data[pointer : pointer+8]))
		pointer += 8

		var inc int

		for i := uint(0); i < keyLen; i++ {

			idx := uint(binary.BigEndian.Uint64(data[pointer : pointer+8]))
			pointer += 8

			rtks.Value[ID][idx] = new(RotationKey)

			if inc, err = rtks.Value[ID][idx].decode(data[pointer:]); err != nil {
				return err
			}

			pointer += inc
		}

	}

	return nil
}
