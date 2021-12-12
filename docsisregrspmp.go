package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISRegRspMp type registration
var LayerTypeDOCSISRegRspMp = gopacket.RegisterLayerType(1004, gopacket.LayerTypeMetadata{Name: "DOCSIS Management Multipart Registration Response", Decoder: gopacket.DecodeFunc(decodeDOCSISRegRspMp)})

// DOCSISRegRspMp is a DOCSIS Management packet header.
type DOCSISRegRspMp struct {
	layers.BaseLayer
	DOCSISBaseRegRsp
	FragmentsTotal byte
	FragmentNumber byte
}

// LayerType returns LayerTypeDOCSISRegRspMp
func (docsis *DOCSISRegRspMp) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISRegRspMp
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSISRegRspMp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return fmt.Errorf("docsis bpkm resp packet is too small for the header")
	}

	docsis.Sid = binary.BigEndian.Uint16(data[0:2])
	docsis.Response = data[2]
	docsis.FragmentsTotal = data[3]
	docsis.FragmentNumber = data[4]

	if err := docsis.parseTLV(data[5:]); err != nil {
		return err
	}

	docsis.Contents = data[:]
	docsis.Payload = data[:0]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSISRegRspMp) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISRegRspMp
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSISRegRspMp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDOCSISRegRspMp(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSISRegRspMp{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
