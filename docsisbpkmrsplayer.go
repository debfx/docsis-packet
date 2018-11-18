package main

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISBpkmRsp type registration
var LayerTypeDOCSISBpkmRsp = gopacket.RegisterLayerType(1003, gopacket.LayerTypeMetadata{Name: "DOCSIS Management Privacy Key Management Response", Decoder: gopacket.DecodeFunc(decodeDOCSISBpkmRsp)})

// DocsisBpkmCodeKeyReply code for Key Reply
const DocsisBpkmCodeKeyReply = 8

// DOCSISBpkmRsp is a DOCSIS Management packet header.
type DOCSISBpkmRsp struct {
	layers.BaseLayer
	Code       byte
	Identifier byte
	Length     uint16
}

// LayerType returns LayerTypeDOCSISBpkmRsp
func (docsis *DOCSISBpkmRsp) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISBpkmRsp
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsis *DOCSISBpkmRsp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return errors.New("docsis bpkm resp packet is too small for the header")
	}

	docsis.Code = data[0]
	docsis.Identifier = data[1]
	docsis.Length = binary.BigEndian.Uint16(data[2:4])

	docsis.Contents = data[:]
	docsis.Payload = data[:0]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsis *DOCSISBpkmRsp) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISBpkmRsp
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsis *DOCSISBpkmRsp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDOCSISBpkmRsp(data []byte, p gopacket.PacketBuilder) error {
	docsis := &DOCSISBpkmRsp{}
	err := docsis.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsis)

	return p.NextDecoder(docsis.NextLayerType())
}
