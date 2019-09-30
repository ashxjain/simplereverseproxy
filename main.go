package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
)

var (
	certFile  = flag.String("cert", "", "A PEM eoncoded certificate file.")
	keyFile   = flag.String("key", "", "A PEM encoded private key file.")
	caFile    = flag.String("CA", "", "A PEM eoncoded CA's certificate file.")
	listenUrl = flag.String("listenUrl", ":8000", "Proxy server address")
	dialUrl   = flag.String("dialUrl", ":8080", "Remote connect address")
	remoteTls = flag.Bool("remoteTls", false, "Remote connection TLS")
)

func main() {
	var err error

	flag.Parse()

	var tlsConfig *tls.Config
	if *certFile != "" && *keyFile != "" {
		serverCerts, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			panic(err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{
				serverCerts,
			},
		}
	}

	var listener net.Listener
	var scheme string
	if tlsConfig != nil {
		listener, err = tls.Listen("tcp", *listenUrl, tlsConfig)
		scheme = "https"
	} else {
		listener, err = net.Listen("tcp", *listenUrl)
		scheme = "http"
	}
	if err != nil {
		panic(err)
	}

	urlObj := strings.Split(*listenUrl, ":")
	if len(urlObj) != 2 {
		panic(fmt.Errorf("invalid listen URL"))
	}

	serverUrl := ""
	if urlObj[0] == "" {
		serverUrl = scheme + "://localhost" + *listenUrl
	} else {
		serverUrl = scheme + "://" + *listenUrl
	}

	fmt.Printf("Starting Proxy Server on %s...\n", serverUrl)
	for {
		client, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		if *remoteTls {
			if *caFile != "" {
				// Load CA cert
				caCert, err := ioutil.ReadFile(*caFile)
				if err != nil {
					panic(err)
				}
				caCertPool, err := x509.SystemCertPool()
				if err != nil {
					panic(err)
				}
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig = &tls.Config{
					RootCAs: caCertPool,
				}
			} else {
				tlsConfig = &tls.Config{
					InsecureSkipVerify: true,
				}
			}
			server, err := tls.Dial("tcp", *dialUrl, tlsConfig)
			if err != nil {
				panic(err)
			}
			go func(client net.Conn, server *tls.Conn) {
				io.Copy(client, server)
			}(client, server)
			go func(client net.Conn, server *tls.Conn) {
				io.Copy(server, client)
			}(client, server)
		} else {
			server, err := net.Dial("tcp", *dialUrl)
			if err != nil {
				panic(err)
			}
			go func(client, server net.Conn) {
				io.Copy(client, server)
			}(client, server)
			go func(client, server net.Conn) {
				io.Copy(server, client)
			}(client, server)
		}
	}
}
