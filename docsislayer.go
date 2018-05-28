package main

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/howeyc/crc16"
)

// LayerTypeDOCSIS type registration
var LayerTypeDOCSIS = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{Name: "DOCSIS", Decoder: gopacket.DecodeFunc(decodeDOCSIS)})

// DOCSIS is a DOCSIS packet header.
type DOCSIS struct {
	layers.BaseLayer
	FCType               uint8
	FCParm               uint8
	ExtHdr               bool
	ExtHdrData           []byte
	CheckSequence        uint16
	CheckSequenceCorrect bool
}

// LayerType returns LayerTypeDOCSIS
func (docsis *DOCSIS) LayerType() gopacket.LayerType {
	return LayerTypeDOCSIS
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSIS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		return errors.New("docsis packet too small")
	}

	docsis.FCType = (data[0] & 0xc0) >> 6 // 0b11000000
	docsis.FCParm = (data[0] & 0x3e) >> 1 // 0b00111110
	docsis.ExtHdr = (data[0] & 0x01) == 1 // 0b00000001

	// skip header for payload
	payloadStart := uint16(6)
	// length field defines the length of extender header + payload
	payloadEnd := int(payloadStart + binary.BigEndian.Uint16(data[2:4]))

	if len(data) < payloadEnd {
		return errors.New("docsis packet smaller than advertised by header")
	}

	if docsis.ExtHdr {
		// skip extender header for payload
		payloadStart += uint16(data[1])
	}

	docsis.CheckSequence = binary.BigEndian.Uint16(data[payloadStart-2 : payloadStart])

	checkSequenceLitteEndian := crc16.ChecksumCCITT(data[:payloadStart-2])
	checkSequenceCalculated := (checkSequenceLitteEndian << 8) | (checkSequenceLitteEndian >> 8)

	docsis.CheckSequenceCorrect = (docsis.CheckSequence == checkSequenceCalculated)
	if !docsis.CheckSequenceCorrect {
		return errors.New("header check sequence doesn't match")
	}

	docsis.Contents = data[:payloadStart]
	docsis.Payload = data[payloadStart:payloadEnd]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSIS) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSIS
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSIS) NextLayerType() gopacket.LayerType {
	if !docsis.CheckSequenceCorrect {
		return gopacket.LayerTypePayload
	}

	if docsis.FCParm == 0 && docsis.FCType == 0 {
		// TODO: actually check the header fields for encryption
		if docsis.ExtHdr {
			return LayerTypeETHENC
		}

		return layers.LayerTypeEthernet
	} else if docsis.FCParm == 1 {
		// TODO management
	}

	return gopacket.LayerTypePayload
}

func decodeDOCSIS(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSIS{}
	docsis.DecodeFromBytes(data, p)
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
