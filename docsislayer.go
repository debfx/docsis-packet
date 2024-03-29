package main

import (
	"encoding/binary"
	"fmt"

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
	ExtHdrPresent        bool
	ExtHdr               []byte
	Encrypted            bool
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
		return fmt.Errorf("docsis packet too small")
	}

	docsis.FCType = (data[0] & 0xc0) >> 6        // 0b11000000
	docsis.FCParm = (data[0] & 0x3e) >> 1        // 0b00111110
	docsis.ExtHdrPresent = (data[0] & 0x01) == 1 // 0b00000001

	// reset attributes
	docsis.ExtHdr = docsis.ExtHdr[:0]
	docsis.Encrypted = false

	// skip header for payload
	payloadStart := uint(6)
	// length field defines the length of extender header + payload
	payloadEnd := uint(payloadStart + uint(binary.BigEndian.Uint16(data[2:4])))

	if uint(len(data)) < payloadEnd {
		return fmt.Errorf("docsis packet smaller than advertised by header")
	}

	if docsis.ExtHdrPresent {
		ehdrStart := payloadStart - 2
		// skip extender header for payload
		payloadStart += uint(data[1])
		ehdrEnd := payloadStart - 2

		if payloadStart > payloadEnd {
			return fmt.Errorf("docsis packet has an invalid extender header length")
		}

		var ehdrLen uint
		for i := ehdrStart; i < ehdrEnd; i += ehdrLen {
			ehdrType := (data[i] & 0xf0) >> 4
			ehdrLen = uint(data[i]&0x0f) + 1

			if ehdrEnd < (i + ehdrLen) {
				return fmt.Errorf("docsis packet has a corrupt extended header")
			}

			// TODO: properly parse extended headers
			docsis.ExtHdr = append(docsis.ExtHdr, ehdrType)

			if ehdrType == 4 && ehdrLen >= 3 && (data[i+2]&0x80) == 0x80 {
				docsis.Encrypted = true
			}
		}
	}

	docsis.CheckSequence = binary.BigEndian.Uint16(data[payloadStart-2 : payloadStart])

	checkSequenceLitteEndian := crc16.ChecksumCCITT(data[:payloadStart-2])
	checkSequenceCalculated := (checkSequenceLitteEndian << 8) | (checkSequenceLitteEndian >> 8)

	docsis.CheckSequenceCorrect = (docsis.CheckSequence == checkSequenceCalculated)
	if !docsis.CheckSequenceCorrect {
		return fmt.Errorf("header check sequence doesn't match")
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

	if docsis.FCType == 0 && docsis.FCParm == 0 {
		if docsis.Encrypted {
			return LayerTypeETHENC
		}

		return layers.LayerTypeEthernet
	} else if docsis.FCType == 3 {
		return LayerTypeDOCSISManagement
	}

	return gopacket.LayerTypePayload
}

func decodeDOCSIS(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSIS{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
