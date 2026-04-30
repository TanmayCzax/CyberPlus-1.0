package main

import (
	"reflect"
	"testing"
)

func TestPingCommandFor_Windows(t *testing.T) {
	name, args := pingCommandFor("windows", "example.com")
	if name != "ping" {
		t.Errorf("expected program 'ping', got %q", name)
	}
	want := []string{"-n", "1", "example.com"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("expected args %v, got %v", want, args)
	}
}

func TestPingCommandFor_Unix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "freebsd", "openbsd"} {
		name, args := pingCommandFor(goos, "example.com")
		if name != "ping" {
			t.Errorf("%s: expected program 'ping', got %q", goos, name)
		}
		want := []string{"-c", "1", "example.com"}
		if !reflect.DeepEqual(args, want) {
			t.Errorf("%s: expected args %v, got %v", goos, want, args)
		}
	}
}

func TestPingCommandFor_PreservesHost(t *testing.T) {
	cases := []string{"127.0.0.1", "localhost", "scanme.nmap.org", "8.8.8.8"}
	for _, host := range cases {
		_, args := pingCommandFor("linux", host)
		if args[len(args)-1] != host {
			t.Errorf("host %q: expected to be last arg, got args=%v", host, args)
		}
	}
}

func TestTracerouteCommandFor_Windows(t *testing.T) {
	name, args := tracerouteCommandFor("windows", "example.com")
	if name != "tracert" {
		t.Errorf("expected program 'tracert', got %q", name)
	}
	want := []string{"example.com"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("expected args %v, got %v", want, args)
	}
}

func TestTracerouteCommandFor_Unix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "freebsd", "openbsd"} {
		name, args := tracerouteCommandFor(goos, "example.com")
		if name != "traceroute" {
			t.Errorf("%s: expected program 'traceroute', got %q", goos, name)
		}
		want := []string{"example.com"}
		if !reflect.DeepEqual(args, want) {
			t.Errorf("%s: expected args %v, got %v", goos, want, args)
		}
	}
}

func TestPingCommand_UsesRuntimeGOOS(t *testing.T) {
	name, args := pingCommand("example.com")
	if name != "ping" {
		t.Errorf("expected program 'ping', got %q", name)
	}
	if len(args) != 3 || args[2] != "example.com" {
		t.Errorf("unexpected args shape: %v", args)
	}
}

func TestTracerouteCommand_UsesRuntimeGOOS(t *testing.T) {
	name, args := tracerouteCommand("example.com")
	if name != "tracert" && name != "traceroute" {
		t.Errorf("expected 'tracert' or 'traceroute', got %q", name)
	}
	want := []string{"example.com"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("expected args %v, got %v", want, args)
	}
}
