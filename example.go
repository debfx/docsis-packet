package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/ziutek/dvb"
)

var docsis DOCSIS
var docsisManagement DOCSISManagement
var docsisRegRspMp DOCSISRegRspMp
var docsisRegRsp DOCSISRegRsp
var parser = gopacket.NewDecodingLayerParser(LayerTypeDOCSIS, &docsis, &docsisManagement, &docsisRegRsp, &docsisRegRspMp)
var decoded = []gopacket.LayerType{}

func decodeLayers(data []byte, decoded *[]gopacket.LayerType) (err error) {
	defer func(e *error) {
		if r := recover(); r != nil {
			*e = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}(&err)

	return parser.DecodeLayers(data, decoded)
}

func parsePacket(packet []byte) {
	err := decodeLayers(packet, &decoded)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decoding some part of the packet:", err)
		return
	}

	for _, layerType := range decoded {
		switch layerType {
		case LayerTypeDOCSISRegRsp:
			fmt.Fprintln(os.Stderr, "DOCSISRegRsp packet for:", docsisManagement.DstMAC.String())
		case LayerTypeDOCSISRegRspMp:
			fmt.Fprintln(os.Stderr, "DOCSISRegRspMp packet for:", docsisManagement.DstMAC.String())
		}
	}
}

func modeReadFile(ctx context.Context, inputFilename string) error {
	var inputReader io.Reader

	if inputFilename == "-" {
		inputReader = os.Stdin
	} else {
		inputFile, err := os.Open(inputFilename)
		if err != nil {
			panic(err)
		}
		defer inputFile.Close()
		inputReader = inputFile
	}

	return readPacketLoop(ctx, inputReader, parsePacket)
}

func modeReadPcap(ctx context.Context, inputFilename string) error {
	var inputReader io.Reader

	if inputFilename == "-" {
		inputReader = os.Stdin
	} else {
		inputFile, err := os.Open(inputFilename)
		if err != nil {
			panic(err)
		}
		defer inputFile.Close()
		inputReader = inputFile
	}

	pcapReader, err := pcapgo.NewReader(inputReader)
	if err != nil {
		return err
	}
	i := 0

	for {
		data, _, err := pcapReader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		parsePacket(data)

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
}

func modeReadDvb(ctx context.Context, frequencyStr string) error {
	var freq int
	var err error
	if freq, err = strconv.Atoi(frequencyStr); err != nil {
		panic(err)
	}

	if err := tune(0, dvb.SysDVBCAnnexA, dvb.QAM256, uint32(freq*1000000), 6952000); err != nil {
		panic(err)
	}

	sr, err := newStreamReader(0, 8190)
	if err != nil {
		panic(err)
	}
	defer sr.Close()

	if err := sr.Start(); err != nil {
		panic(err)
	}

	if err := readPacketLoop(ctx, &sr, parsePacket); err != nil {
		sr.Stop()
		return err
	}

	if err := sr.Stop(); err != nil {
		return err
	}

	return nil
}

func modeBenchmark(frequencyStr string, duration time.Duration) error {
	var frequency int
	var err error
	if frequency, err = strconv.Atoi(frequencyStr); err != nil {
		panic(err)
	}

	streamReader, err := newStreamReader(0, 8190)
	if err != nil {
		panic(err)
	}
	defer streamReader.Close()

	if err := tune(0, dvb.SysDVBCAnnexA, dvb.QAM256, uint32(frequency*1000000), 6952000); err != nil {
		return err
	}

	if err := streamReader.Start(); err != nil {
		return err
	}
	defer streamReader.Stop()

	benchBuffer := make([]byte, 1024*packetSize)
	var read int
	readTotal := 0

	streamReader.SetReadDeadline(time.Now().Add(duration))
	defer streamReader.SetReadDeadline(time.Time{})
	t := time.Now()

	for {
		if read, err = streamReader.Read(benchBuffer); err != nil {
			if os.IsTimeout(err) {
				break
			} else {
				return err
			}
		}
		readTotal += read
	}
	dt := time.Now().Sub(t)
	result := int(time.Duration(readTotal*8) * time.Second / dt)
	fmt.Println("Benchmark:", result, "bps")
	return nil
}

func main() {
	mode := os.Args[1]
	parameter := os.Args[2]

	// we want to decode packets only partically
	parser.IgnoreUnsupported = true
	// we install an own recover handler to print a stacktrace
	parser.IgnorePanic = true

	// cancel ctx on SIGTERM / SIGINT allowing graceful shutdown
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)
	go func() {
		<-c
		cancel()
	}()

	var err error

	if mode == "readraw" {
		// read raw dvb stream, for example from dvbsnoop
		err = modeReadFile(ctx, parameter)
	} else if mode == "readpcap" {
		// read PCAP file
		err = modeReadPcap(ctx, parameter)
	} else if mode == "readdvb" {
		// capture first dvb device at specified frequency (in mhz)
		err = modeReadDvb(ctx, parameter)
	} else if mode == "benchmark" {
		// calculate average data transfer rate on specified frequency (in mhz)
		err = modeBenchmark(parameter, 10*time.Second)
	}

	if err != nil && err != context.Canceled {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Bye!\n")
}
