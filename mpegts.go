package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
)

type processPacket func(packet []byte)

const packetSize = 188

func payloadUnitStartIndicator(packet []byte) bool {
	return (packet[1] & 0x040) != 0 // 0b1000000
}

func assemblePacket(buffer *bytes.Buffer, data []byte, fn processPacket) {
	if len(data) != packetSize {
		return
	}

	// check for sync byte
	if data[0] != 0x47 {
		return
	}

	// the pointer field defines the end of the first payload packet if it's the last
	// part of a payload packet that's split across multiple TS packets
	// otherwise the field is 0
	pointerField := data[4]
	// skip header
	curIndex := 5

	if pointerField != 0 {
		// we have encountered the trailing part of a packet
		if packetSize < (curIndex + int(pointerField)) {
			buffer.Reset()
			return
		}
		buffer.Write(data[curIndex : curIndex+int(pointerField)])
		fn(buffer.Bytes())
		buffer.Reset()
		curIndex += int(pointerField)
	}

	for {
		// skip any stuffing bytes
		for ; curIndex < packetSize && data[curIndex] == 0xff; curIndex++ {
		}
		if curIndex == packetSize {
			// end of TS packet reached
			return
		}

		if packetSize >= (curIndex + 4) {
			// peek into the length field of the payload (DOCSIS) packet
			lengthField := int(binary.BigEndian.Uint16(data[curIndex+2 : curIndex+4]))
			// the length field specifies the number of bytes of extended header + payload
			// add 6 (header length) to get the full length
			end := curIndex + lengthField + 6

			// if we have the whole packet, process it now
			if end < packetSize {
				// we've encountered a comlete payload packet
				// parse and then continue to scan for another packet
				buffer.Write(data[curIndex:end])
				fn(buffer.Bytes())
				buffer.Reset()
				curIndex = end
				continue
			}
		}

		// this is an incomplete payload packet
		// the remaining parts are in the next TS packets
		buffer.Write(data[curIndex:])
		return
	}
}

func readPacket(buffer *bytes.Buffer, packet []byte, fn processPacket) {
	if payloadUnitStartIndicator(packet) {
		// TS packet contains a payload packet border
		// we need to properly parse the packet
		assemblePacket(buffer, packet, fn)
	} else {
		// we are in the middle of a payload packet
		// just fill our buffer while ignoring the TS header
		buffer.Write(packet[4:])
	}
}

func readPacketLoop(ctx context.Context, inputReader io.Reader, fn processPacket) error {
	var buffer bytes.Buffer
	packet := make([]byte, packetSize)
	// large enough buffer to avoid too much syscall overhead through small reads
	bufferedReader := bufio.NewReaderSize(inputReader, 25*packetSize)

	var err error
	var read int
	i := 0
	for read, err = io.ReadFull(bufferedReader, packet); read > 0 && err == nil; read, err = io.ReadFull(bufferedReader, packet) {
		readPacket(&buffer, packet, fn)

		if i%10 == 0 {
			select {
			case <-ctx.Done():
				// ctx is canceled
				return ctx.Err()
			default:
				// ctx is not canceled, continue immediately
			}
		}
		i++
	}

	return err
}
