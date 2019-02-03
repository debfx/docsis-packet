package main

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeDOCSISManagement type registration
var LayerTypeDOCSISManagement = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{Name: "DOCSIS Management", Decoder: gopacket.DecodeFunc(decodeDOCSISManagement)})

// DocsisManagementRegRsp code for DOCSIS Management Registration Response
const DocsisManagementRegRsp = 7

// DocsisManagementBpkmRsp code for Baseline Privacy Key Management Response
const DocsisManagementBpkmRsp = 13

// DocsisManagementRegRspMp code for DOCSIS Management Multipart Registration Response
const DocsisManagementRegRspMp = 45

// DOCSISManagement is a DOCSIS Management packet header.
type DOCSISManagement struct {
	layers.BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
	MessageLength  uint16
	DSAP           byte
	SSAP           byte
	Control        byte
	Version        byte
	Type           byte
	Reserved       byte
}

// LayerType returns LayerTypeDOCSISManagement
func (docsisManagement *DOCSISManagement) LayerType() gopacket.LayerType {
	return LayerTypeDOCSISManagement
}

// DecodeFromBytes decodes the given bytes into this layer.
func (docsisManagement *DOCSISManagement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errors.New("docsis management packet is too small for the header")
	}

	docsisManagement.DstMAC = net.HardwareAddr(data[0:6])
	docsisManagement.SrcMAC = net.HardwareAddr(data[6:12])
	docsisManagement.MessageLength = binary.BigEndian.Uint16(data[12:14])
	docsisManagement.DSAP = data[14]
	docsisManagement.SSAP = data[15]
	docsisManagement.Control = data[16]
	docsisManagement.Version = data[17]
	docsisManagement.Type = data[18]
	docsisManagement.Reserved = data[19]

	payloadStart := 20
	// len(DstMAC) + len(SrcMAC) + len(MessageLength) + MessageLength
	payloadEnd := int(6 + 6 + 2 + docsisManagement.MessageLength)

	if len(data) < payloadEnd {
		return errors.New("docsis management packet is too small for the payload")
	}

	docsisManagement.Contents = data[:payloadStart]
	docsisManagement.Payload = data[payloadStart:payloadEnd]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (docsisManagement *DOCSISManagement) CanDecode() gopacket.LayerClass {
	return LayerTypeDOCSISManagement
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (docsisManagement *DOCSISManagement) NextLayerType() gopacket.LayerType {
	if docsisManagement.Type == DocsisManagementRegRsp {
		return LayerTypeDOCSISRegRsp
	} else if docsisManagement.Type == DocsisManagementBpkmRsp {
		return LayerTypeDOCSISBpkmRsp
	} else if docsisManagement.Type == DocsisManagementRegRspMp {
		return LayerTypeDOCSISRegRspMp
	}

	return gopacket.LayerTypePayload
}

func decodeDOCSISManagement(data []byte, p gopacket.PacketBuilder) error {
	docsisManagement := &DOCSISManagement{}
	err := docsisManagement.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(docsisManagement)

	return p.NextDecoder(docsisManagement.NextLayerType())
}
