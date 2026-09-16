// origin is a tiny test origin server for dldw smoke tests: it serves
// synthetic artifacts with Range support under /org/repo/releases/download/.
//
//	go run ./scripts/origin -addr 127.0.0.1:9999 -size 8388608
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address")
	size := flag.Int64("size", 4<<20, "artifact size in bytes")
	flag.Parse()

	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i * 31 % 251)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/org/repo/releases/download/v1/app.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "app.tar.gz", time.Time{}, newSeeker(payload))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin ok (%s %s), size=%d", r.Method, r.URL.Path, *size)
	})

	log.Printf("origin listening on http://%s (artifact %d bytes)", *addr, *size)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

type seeker struct {
	b   []byte
	off int64
}

func newSeeker(b []byte) *seeker { return &seeker{b: b} }

func (s *seeker) Read(p []byte) (int, error) {
	if s.off >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.off:])
	s.off += int64(n)
	return n, nil
}

func (s *seeker) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case 0:
		s.off = off
	case 1:
		s.off += off
	case 2:
		s.off = int64(len(s.b)) + off
	}
	return s.off, nil
}
