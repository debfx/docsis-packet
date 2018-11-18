package main

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISRegRsp type registration
var LayerTypeDOCSISRegRsp = gopacket.RegisterLayerType(1005, gopacket.LayerTypeMetadata{Name: "DOCSIS Management Registration Response", Decoder: gopacket.DecodeFunc(decodeDOCSISRegRsp)})

// DOCSISRegEsp is a DOCSIS Management packet header.
type DOCSISRegEsp struct {
	layers.BaseLayer
	Sid               uint16
	Response          byte
	FragmentsTotal    byte
	FragmentNumber    byte
	DownstreamMaxRate uint32
	UpstreamMaxRate   uint32
}

// LayerType returns LayerTypeDOCSISRegRsp
func (docsis *DOCSISRegEsp) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISRegRsp
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSISRegEsp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return errors.New("docsis bpkm resp packet is too small for the header")
	}

	docsis.Sid = binary.BigEndian.Uint16(data[0:2])
	docsis.Response = data[2]

	var err error
	docsis.DownstreamMaxRate, docsis.UpstreamMaxRate, err = parseTLV(data[3:])
	if err != nil {
		return err
	}

	docsis.Contents = data[:]
	docsis.Payload = data[:0]

	return nil
}

func parseTLV(tlv []byte) (uint32, uint32, error) {
	upstreamMaxRate := uint32(0)
	downstreamMaxRate := uint32(0)

	var tlvTypeLen int
	for i := 0; i < len(tlv); i += tlvTypeLen + 2 {
		if len(tlv) <= (i + 1) {
			return 0, 0, errors.New("tlv header too small")
		}

		tlvType := tlv[i]
		tlvTypeLen = int(tlv[i+1])
		if len(tlv) < (i + 2 + tlvTypeLen) {
			return 0, 0, errors.New("tlv too small")
		}

		tlvInner := tlv[i+2 : i+2+tlvTypeLen]
		var tlvInnerTypeLen int
		var flowRef uint16
		var maxSustainedRate uint32
		for j := 0; j < len(tlvInner); j += tlvInnerTypeLen + 2 {
			if len(tlv) <= (j + 1) {
				return 0, 0, errors.New("tlv inner header too small")
			}
			tlvInnerType := tlvInner[j]
			tlvInnerTypeLen = int(tlvInner[j+1])
			if len(tlv) < (j + 2 + tlvInnerTypeLen) {
				return 0, 0, errors.New("tlv inner too small")
			}

			innerData := tlvInner[j+2 : j+2+tlvInnerTypeLen]

			if tlvType == 24 || tlvType == 25 {
				if tlvInnerType == 1 {
					if tlvInnerTypeLen != 2 {
						return 0, 0, errors.New("docsis reg esp tlv inner type len too small")
					}
					flowRef = binary.BigEndian.Uint16(innerData)
				} else if tlvInnerType == 8 {
					if tlvInnerTypeLen != 4 {
						return 0, 0, errors.New("docsis reg esp tlv inner type len too small")
					}
					maxSustainedRate = binary.BigEndian.Uint32(innerData)
				}
			}
		}

		if tlvType == 24 && flowRef == 1 && maxSustainedRate != 0 {
			upstreamMaxRate = maxSustainedRate
		} else if tlvType == 25 && flowRef == 2 && maxSustainedRate != 0 {
			downstreamMaxRate = maxSustainedRate
		}
	}

	return downstreamMaxRate, upstreamMaxRate, nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSISRegEsp) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISRegRsp
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSISRegEsp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDOCSISRegRsp(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSISRegEsp{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}