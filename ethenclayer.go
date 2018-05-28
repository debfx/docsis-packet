package main

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeETHENC type registration
var LayerTypeETHENC = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{Name: "ETHENC", Decoder: gopacket.DecodeFunc(decodeETHENC)})

// ETHENC is a ETHENC packet header.
type ETHENC struct {
	layers.BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   uint16
}

// LayerType returns LayerTypeETHENC
func (ethenc *ETHENC) LayerType() gopacket.LayerType {
	return LayerTypeETHENC
}

// DecodeFromBytes decodes the given bytes into this layer.
func (ethenc *ETHENC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}

	ethenc.DstMAC = net.HardwareAddr(data[0:6])
	ethenc.SrcMAC = net.HardwareAddr(data[6:12])
	ethenc.EthernetType = binary.BigEndian.Uint16(data[12:14])
	ethenc.Contents = data[:14]
	ethenc.Payload = data[14:]
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (ethenc *ETHENC) CanDecode() gopacket.LayerClass {
	return LayerTypeETHENC
}

func decodeETHENC(data []byte, p gopacket.PacketBuilder) error {
	ethenc := &ETHENC{}
	ethenc.DecodeFromBytes(data, p)
	p.AddLayer(ethenc)
	return p.NextDecoder(gopacket.LayerTypePayload)
}
