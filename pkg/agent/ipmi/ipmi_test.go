package ipmi_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
)

func TestSDRAndReadings(t *testing.T) {
	b := fakebmc.X11SCAF()
	ctx := context.Background()
	sensors, err := ipmi.ReadSDR(ctx, b)
	if err != nil || len(sensors) != 6 {
		t.Fatal(len(sensors), err)
	}
	if sensors[0].Name != "CPU Temp" || sensors[0].Type != ipmi.TypeTemperature || *sensors[0].UpperCritical() != 100 {
		t.Fatalf("%+v", sensors[0])
	}
	r, err := ipmi.ReadSensors(ctx, b, sensors)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, x := range r {
		got[x.Sensor.Name] = x.Value
	}
	want := map[string]float64{"CPU Temp": 45, "PCH Temp": 48, "FAN1": 1400, "FANA": 900, "12V": 12.12}
	if !reflect.DeepEqual(got, want) { // FAN2 (empty header) left out
		t.Fatal(got)
	}
}

func TestConversionSigned(t *testing.T) {
	rec := fakebmc.FullSensor(0, 1, ipmi.TypeTemperature, "Ambient", -3, -12, -1, 1, 2, 0) // negative M, B, exps
	s, ok := ipmi.ParseFullSensor(rec)
	if !ok {
		t.Fatal("parse")
	}
	// y = (M*x + B*10^Bexp) * 10^Rexp with x = int8(0xF6) = -10: (-3*-10 + -12*10) * 0.1 = -9
	if v := s.Convert(0xF6); v != -9 {
		t.Fatal(v)
	}
	if _, ok := ipmi.ParseFullSensor(rec[:20]); ok {
		t.Fatal("short record")
	}
	other := append([]byte{}, rec...)
	other[5] = 0x2C // owned by another controller
	if _, ok := ipmi.ParseFullSensor(other); ok {
		t.Fatal("foreign owner")
	}
}

func TestSupermicroFan(t *testing.T) {
	b := fakebmc.X11SCAF()
	ctx := context.Background()
	if m, err := ipmi.GetFanMode(ctx, b); err != nil || m != "optimal" {
		t.Fatal(m, err)
	}
	if err := ipmi.SetFanMode(ctx, b, "full"); err != nil {
		t.Fatal(err)
	}
	if err := ipmi.SetDuty(ctx, b, 0, 40); err != nil {
		t.Fatal(err)
	}
	if d, _ := ipmi.GetDuty(ctx, b, 0); d != 40 {
		t.Fatal(d)
	}
	if err := ipmi.SetFanMode(ctx, b, "pue"); err == nil {
		t.Fatal("pue is not settable")
	}
	if err := ipmi.SetDuty(ctx, b, 0, 101); err == nil {
		t.Fatal("over 100")
	}
	if _, err := ipmi.GetDuty(ctx, b, 3); !ipmi.IsCompletion(err, 0xCC) || !strings.Contains(err.Error(), "invalid data field") {
		t.Fatal(err)
	}
	if ipmi.ModeName(9) != "unknown(9)" {
		t.Fatal("unknown mode")
	}
}

func TestIpmitoolArgsAndOutput(t *testing.T) {
	in := &ipmi.Ipmitool{Path: "/usr/bin/ipmitool"}
	if a := in.Args(0x30, 0x70, []byte{0x66, 0x01, 0x00, 0x32}); strings.Join(a, " ") != "raw 0x30 0x70 0x66 0x01 0x00 0x32" {
		t.Fatal(a)
	}
	lan := &ipmi.Ipmitool{Host: "192.168.1.5", Username: "fairy", Password: "secret"}
	a := strings.Join(lan.Args(0x30, 0x45, []byte{0}), " ")
	if a != "-I lanplus -H 192.168.1.5 -U fairy -E raw 0x30 0x45 0x00" || strings.Contains(a, "secret") {
		t.Fatal(a)
	}
	if b, err := ipmi.ParseRawOutput(" 01 0a\n ff\n"); err != nil || !reflect.DeepEqual(b, []byte{1, 10, 255}) {
		t.Fatal(b, err)
	}
	if _, err := ipmi.ParseRawOutput("Unable to send"); err == nil {
		t.Fatal("garbage")
	}
}

func TestWMIProtocol(t *testing.T) {
	if r := ipmi.FormatWMIRequest(0x30, 0x70, []byte{0x66, 0, 1}); r != "48 112 102,0,1\n" {
		t.Fatal(r)
	}
	if r := ipmi.FormatWMIRequest(0x0A, 0x22, nil); r != "10 34 \n" {
		t.Fatal(r)
	}
	if d, err := ipmi.ParseWMIResponse("OK 00 0002"); err != nil || !reflect.DeepEqual(d, []byte{0x02}) {
		t.Fatal(d, err) // first byte of ResponseData is the completion code
	}
	if _, err := ipmi.ParseWMIResponse("OK c1 c1"); !ipmi.IsCompletion(err, 0xC1) {
		t.Fatal(err)
	}
	if _, err := ipmi.ParseWMIResponse("ERR Access denied"); err == nil || !strings.Contains(err.Error(), "Access denied") {
		t.Fatal(err)
	}
	if _, err := ipmi.ParseWMIResponse("garbage"); err == nil {
		t.Fatal("garbage")
	}
	if len(ipmi.EncodedWMIScript()) < 100 {
		t.Fatal("script")
	}
}
