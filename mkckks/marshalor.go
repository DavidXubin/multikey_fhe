package mkckks

import (
	"encoding/binary"
	"errors"
	"math"

	"mk-lr/mkrlwe"

	"github.com/ldsec/lattigo/v2/ring"
)

// GetDataLen returns the length in bytes of the target Ciphertext.
func (ciphertext *Ciphertext) GetDataLen(WithMetaData bool) (dataLen int) {
	// MetaData is :
	// 1 byte : Degree
	// 9 byte : Scale
	// 1 byte : isNTT
	if WithMetaData {
		dataLen += 10
	}

	for ID, el := range ciphertext.Value {
		if WithMetaData {
			//用于存放字符串ID
			dataLen += 1
		}
		dataLen += len(ID)

		dataLen += el.GetDataLen(WithMetaData)
	}

	return dataLen
}

// MarshalBinary encodes a Ciphertext on a byte slice. The total size
// in byte is 4 + 8* N * numberModuliQ * (degree + 1).
func (ciphertext *Ciphertext) MarshalBinary() (data []byte, err error) {

	data = make([]byte, ciphertext.GetDataLen(true))

	data[0] = uint8(ciphertext.Degree() + 1)

	binary.LittleEndian.PutUint64(data[1:9], math.Float64bits(ciphertext.Scale))

	var pointer, inc int

	pointer = 10

	for ID, el := range ciphertext.Value {
		data[pointer] = uint8(len(ID))
		pointer += 1

		copy(data[pointer:], []byte(ID))
		pointer += len(ID)

		if inc, err = el.WriteTo(data[pointer:]); err != nil {
			return nil, err
		}

		pointer += inc
	}

	return data, nil
}

// UnmarshalBinary decodes a previously marshaled Ciphertext on the target Ciphertext.
func (ciphertext *Ciphertext) UnmarshalBinary(data []byte) (err error) {
	if len(data) < 10 { // cf. ciphertext.GetDataLen()
		return errors.New("too small bytearray")
	}

	ciphertext.Ciphertext = new(mkrlwe.Ciphertext)

	ciphertext.Value = make(map[string]*ring.Poly)

	ciphertext.Scale = math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))

	var pointer, inc int
	pointer = 10

	for pointer < len(data) {
		idLen := int(data[pointer])
		pointer += 1

		ID := string(data[pointer : pointer+idLen])
		pointer += idLen

		ciphertext.Value[ID] = new(ring.Poly)

		if inc, err = ciphertext.Value[ID].DecodePolyNew(data[pointer:]); err != nil {
			return err
		}

		pointer += inc
	}

	if pointer != len(data) {
		return errors.New("remaining unparsed data")
	}

	return nil
}
