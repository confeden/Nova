package warp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

// recordWrites sends each payload through the conn built by wrap over one end of a net.Pipe and
// returns the chunk sizes the other end received. net.Pipe hands one Write to one Read (the read
// buffer is larger than any chunk), so chunk boundaries are observable exactly.
func recordWrites(t *testing.T, wrap func(net.Conn) net.Conn, payloads ...[]byte) []int {
	t.Helper()
	client, server := net.Pipe()
	var chunks []int
	var received bytes.Buffer
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				chunks = append(chunks, n)
				received.Write(buf[:n])
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				done <- err
				return
			}
		}
	}()
	conn := wrap(client)
	var sent bytes.Buffer
	for _, p := range payloads {
		n, err := conn.Write(p)
		if err != nil || n != len(p) {
			t.Fatalf("Write = %d, %v; want %d", n, err, len(p))
		}
		sent.Write(p)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent.Bytes(), received.Bytes()) {
		t.Fatal("bytes changed in transit")
	}
	return chunks
}

func payload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

func TestFragmentSplitPlanThenRemainder(t *testing.T) {
	profile := registrationProfile{splitPlan: []int{1, 255, 256}, fragmentBytes: 512, fragmentDelay: time.Millisecond}
	got := recordWrites(t, func(c net.Conn) net.Conn { return newFragmentedConn(c, profile) }, payload(1000), payload(100))
	want := []int{1, 255, 256, 488, 100}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunks = %v, want %v", got, want)
	}
}

func TestFragmentFixedSize(t *testing.T) {
	profile := registrationProfile{fragmentSize: 16, fragmentBytes: 64}
	got := recordWrites(t, func(c net.Conn) net.Conn { return newFragmentedConn(c, profile) }, payload(100))
	want := []int{16, 16, 16, 16, 36}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunks = %v, want %v", got, want)
	}
}

// A first write shorter than the budget leaves budget for the next write, which is then cut with
// the fragment size set from the first limit — register.go behaves the same way.
func TestFragmentBudgetSpansWrites(t *testing.T) {
	profile := registrationProfile{splitPlan: []int{1, 663}, fragmentBytes: 664}
	got := recordWrites(t, func(c net.Conn) net.Conn { return newFragmentedConn(c, profile) }, payload(300), payload(500), payload(50))
	want := []int{1, 299, 300, 64, 136, 50}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunks = %v, want %v", got, want)
	}
}

func TestFragmentSkipsNonPositivePlanEntries(t *testing.T) {
	profile := registrationProfile{splitPlan: []int{0, 5, -1, 5}, fragmentBytes: 10}
	got := recordWrites(t, func(c net.Conn) net.Conn { return newFragmentedConn(c, profile) }, payload(20))
	want := []int{5, 5, 10}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunks = %v, want %v", got, want)
	}
}

func TestFragmentPayloadShorterThanFirstChunk(t *testing.T) {
	profile := registrationProfile{fragmentSize: 32, fragmentBytes: 768}
	got := recordWrites(t, func(c net.Conn) net.Conn { return newFragmentedConn(c, profile) }, payload(20))
	want := []int{20}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunks = %v, want %v", got, want)
	}
}

func TestFragmentNoPlanIsIdentity(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if got := newFragmentedConn(client, registrationProfile{fragmentBytes: 512}); got != client {
		t.Fatal("a profile without a plan or size must not wrap the conn")
	}
}

func TestFragmentWriteErrorReportsWritten(t *testing.T) {
	client, server := net.Pipe()
	profile := registrationProfile{fragmentSize: 4, fragmentBytes: 16}
	conn := newFragmentedConn(client, profile)
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf) // take the first chunk, then hang up
		_ = server.Close()
	}()
	n, err := conn.Write(payload(32))
	if err == nil {
		t.Fatal("write after the peer closed must fail")
	}
	if n != 4 {
		t.Fatalf("written = %d, want 4", n)
	}
}
