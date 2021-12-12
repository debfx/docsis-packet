package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISRegRsp type registration
var LayerTypeDOCSISRegRsp = gopacket.RegisterLayerType(1005, gopacket.LayerTypeMetadata{Name: "DOCSIS Management Registration Response", Decoder: gopacket.DecodeFunc(decodeDOCSISRegRsp)})

type DOCSISBaseRegRsp struct {
	Sid                uint16
	Response           byte
	DocsisVersion      byte
	UpstreamChannels   byte
	DownstreamChannels byte
	DownstreamMaxRate  uint32
	UpstreamMaxRate    uint32
}

// DOCSISRegRsp is a DOCSIS Management packet header.
type DOCSISRegRsp struct {
	layers.BaseLayer
	DOCSISBaseRegRsp
}

// LayerType returns LayerTypeDOCSISRegRsp
func (docsis *DOCSISRegRsp) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISRegRsp
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSISRegRsp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return fmt.Errorf("docsis bpkm resp packet is too small for the header")
	}

	docsis.Sid = binary.BigEndian.Uint16(data[0:2])
	docsis.Response = data[2]

	if err := docsis.parseTLV(data[3:]); err != nil {
		return err
	}

	docsis.Contents = data[:]
	docsis.Payload = data[:0]

	return nil
}

func (docsis *DOCSISBaseRegRsp) parseTLV(tlv []byte) error {
	docsisVersion := byte(0)
	upstreamChannels := byte(0)
	downstreamChannels := byte(0)
	upstreamMaxRate := uint32(0)
	downstreamMaxRate := uint32(0)

	var tlvTypeLen int
	for i := 0; i < len(tlv); i += tlvTypeLen + 2 {
		if len(tlv) < (i + 2) {
			return fmt.Errorf("tlv header too small")
		}

		tlvType := tlv[i]
		tlvTypeLen = int(tlv[i+1])
		if len(tlv) < (i + 2 + tlvTypeLen) {
			return fmt.Errorf("tlv too small")
		}

		// only parse inner structure if the tlvType has one and we are interested in the content
		if tlvType != 5 && tlvType != 24 && tlvType != 25 {
			continue
		}

		tlvInner := tlv[i+2 : i+2+tlvTypeLen]
		var tlvInnerTypeLen int
		var flowRef uint16
		var maxSustainedRate uint32
		for j := 0; j < len(tlvInner); j += tlvInnerTypeLen + 2 {
			if len(tlvInner) < (j + 2) {
				return fmt.Errorf("tlv inner header too small")
			}
			tlvInnerType := tlvInner[j]
			tlvInnerTypeLen = int(tlvInner[j+1])
			if len(tlvInner) < (j + 2 + tlvInnerTypeLen) {
				return fmt.Errorf("tlv inner too small")
			}

			innerData := tlvInner[j+2 : j+2+tlvInnerTypeLen]

			if tlvType == 5 {
				if tlvInnerType == 2 {
					if tlvInnerTypeLen != 1 {
						return fmt.Errorf("docsis reg esp tlv inner type len too small")
					}
					docsisVersion = innerData[0]
				} else if tlvInnerType == 24 {
					if tlvInnerTypeLen != 1 {
						return fmt.Errorf("docsis reg esp tlv inner type len too small")
					}
					upstreamChannels = innerData[0]
				} else if tlvInnerType == 29 {
					if tlvInnerTypeLen != 1 {
						return fmt.Errorf("docsis reg esp tlv inner type len too small")
					}
					downstreamChannels = innerData[0]
				}
			} else if tlvType == 24 || tlvType == 25 {
				if tlvInnerType == 1 {
					if tlvInnerTypeLen != 2 {
						return fmt.Errorf("docsis reg esp tlv inner type len too small")
					}
					flowRef = binary.BigEndian.Uint16(innerData)
				} else if tlvInnerType == 8 {
					if tlvInnerTypeLen != 4 {
						return fmt.Errorf("docsis reg esp tlv inner type len too small")
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

	docsis.DocsisVersion = docsisVersion
	docsis.UpstreamChannels = upstreamChannels
	docsis.DownstreamChannels = downstreamChannels
	docsis.UpstreamMaxRate = upstreamMaxRate
	docsis.DownstreamMaxRate = downstreamMaxRate

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSISRegRsp) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISRegRsp
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSISRegRsp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDOCSISRegRsp(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSISRegRsp{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
