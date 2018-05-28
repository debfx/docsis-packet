package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/google/gopacket"
)

func parsePacket(packet []byte) {
	docsisPacket := gopacket.NewPacket(packet, LayerTypeDOCSIS, gopacket.NoCopy)
	if err := docsisPacket.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
		return
	}

	fmt.Printf("Parsed packet: start=%x, end=%x\n", docsisPacket.Data()[:3], docsisPacket.Data()[len(docsisPacket.Data())-3:])
}

func main() {
	packet := make([]byte, packetSize)
	var bufferStore []byte
	buffer := bytes.NewBuffer(bufferStore)

	for read, err := os.Stdin.Read(packet); read > 0 && err == nil; read, err = os.Stdin.Read(packet) {
		readPacket(buffer, packet, parsePacket)
	}
}
