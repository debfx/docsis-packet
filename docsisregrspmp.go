package main

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISRegRspMp type registration
var LayerTypeDOCSISRegRspMp = gopacket.RegisterLayerType(1004, gopacket.LayerTypeMetadata{Name: "DOCSIS Management Multipart Registration Response", Decoder: gopacket.DecodeFunc(decodeDOCSISRegRspMp)})

// DOCSISRegEspMp is a DOCSIS Management packet header.
type DOCSISRegEspMp struct {
	layers.BaseLayer
	Sid               uint16
	Response          byte
	FragmentsTotal    byte
	FragmentNumber    byte
	DownstreamMaxRate uint32
	UpstreamMaxRate   uint32
}

// LayerType returns LayerTypeDOCSISRegRspMp
func (docsis *DOCSISRegEspMp) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISRegRspMp
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSISRegEspMp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return errors.New("docsis bpkm resp packet is too small for the header")
	}

	docsis.Sid = binary.BigEndian.Uint16(data[0:2])
	docsis.Response = data[2]
	docsis.FragmentsTotal = data[3]
	docsis.FragmentNumber = data[4]

	var err error
	docsis.DownstreamMaxRate, docsis.UpstreamMaxRate, err = parseTLV(data[5:])
	if err != nil {
		return err
	}

	docsis.Contents = data[:]
	docsis.Payload = data[:0]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSISRegEspMp) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISRegRspMp
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSISRegEspMp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDOCSISRegRspMp(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSISRegEspMp{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
