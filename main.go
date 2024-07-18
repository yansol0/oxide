package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func handleHttp(w http.ResponseWriter, r *http.Request) {
	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer res.Body.Close()

	for k, vv := range r.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func main() {
	var pemPath string
	var keyPath string
	var proto string

	flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&keyPath, "key", "server.key", "path to keyfile")
	flag.StringVar(&proto, "proto", "https", "proxy protocol (http or https)")
	flag.Parse()

	if proto != "http" && proto != "https" {
		log.Fatal("unsupported protocol")
	}

	server := &http.Server{
		Addr: ":1337",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHttp(w, r)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	if proto == "http" {
		log.Fatal(server.ListenAndServe())
	} else {
		log.Fatal(server.ListenAndServeTLS(pemPath, keyPath))
	}
}
