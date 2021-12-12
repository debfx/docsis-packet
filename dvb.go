package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ziutek/dvb"
	"github.com/ziutek/dvb/linuxdvb/demux"
	"github.com/ziutek/dvb/linuxdvb/frontend"
)

func waitForTune(fe frontend.Device, deadline time.Time) error {
	fe3 := frontend.API3{Device: fe}
	var ev frontend.Event
	for ev.Status()&frontend.HasLock == 0 {
		timedout, err := fe3.WaitEvent(&ev, deadline)
		if err != nil {
			return err
		}
		if timedout {
			return fmt.Errorf("tuning timeout")
		}
	}
	return nil
}

func tune(deviceNum int, ds dvb.DeliverySystem, modulation dvb.Modulation, freqHz uint32, bd uint32) error {
	fe, err := frontend.Open(fmt.Sprintf("/dev/dvb/adapter%d/frontend0", deviceNum))
	if err != nil {
		return err
	}
	defer fe.Close()

	if err = fe.SetDeliverySystem(ds); err != nil {
		return err
	}
	if err = fe.SetModulation(modulation); err != nil {
		return err
	}
	if err = fe.SetFrequency(freqHz); err != nil {
		return err
	}
	if err = fe.SetInversion(dvb.InversionAuto); err != nil {
		return err
	}
	if err = fe.SetSymbolRate(bd); err != nil {
		return err
	}
	if err = fe.SetInnerFEC(dvb.FECAuto); err != nil {
		return err
	}

	if err = fe.Tune(); err != nil {
		return err
	}

	if err = waitForTune(fe, time.Now().Add(5*time.Second)); err != nil {
		return fmt.Errorf("failed to tune to modulation=%d freq=%d bd=%d: %w", modulation, freqHz, bd, err)
	}

	return nil
}

type StreamReader struct {
	filter  demux.StreamFilter
	fileDvr *os.File
}

func newStreamReader(deviceNum int, pid int16) (StreamReader, error) {
	var sr StreamReader
	var err error
	dmx := demux.Device(fmt.Sprintf("/dev/dvb/adapter%d/demux0", deviceNum))
	sr.filter, err = dmx.NewStreamFilter(
		&demux.StreamFilterParam{
			Pid:  pid,
			In:   demux.InFrontend,
			Out:  demux.OutTSTap,
			Type: demux.Other,
		},
	)
	if err != nil {
		return sr, err
	}

	if err = sr.filter.SetBufferSize(1024 * 188); err != nil {
		sr.Close()
		return sr, err
	}

	sr.fileDvr, err = os.Open(fmt.Sprintf("/dev/dvb/adapter%d/dvr0", deviceNum))
	if err != nil {
		sr.Close()
		return sr, err
	}

	return sr, nil
}

func (sr *StreamReader) Start() error {
	return sr.filter.Start()
}

func (sr *StreamReader) Stop() error {
	return sr.filter.Stop()
}

func (sr *StreamReader) Read(p []byte) (n int, err error) {
	return sr.fileDvr.Read(p)
}

func (sr *StreamReader) Close() {
	sr.fileDvr.Close()
	sr.filter.Close()
}

func (sr *StreamReader) SetReadDeadline(t time.Time) error {
	return sr.fileDvr.SetReadDeadline(t)
}
