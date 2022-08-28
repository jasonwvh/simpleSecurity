package main

import (
	"crypto/tls"
	"log"
)

func CheckConnection(ep string) (bool, error) {
	log.Printf("establishing conection to %s", ep)

	conn, err := tls.Dial("tcp", ep, &tls.Config{})
	if err != nil {
		return false, err
	}

	log.Printf("connection established to %s", conn.RemoteAddr().String())
	return true, nil
}

func CheckTLS(ep string) (map[string]bool, error) {
	log.Printf("checking protocols (%s)", ep)
	res := make(map[string]bool)

	versions := map[uint16]string{
		tls.VersionSSL30: "SSL",
		tls.VersionTLS10: "TLS10",
		tls.VersionTLS11: "TLS11",
		tls.VersionTLS12: "TLS12",
		tls.VersionTLS13: "TLS13",
	}

	for k, v := range versions {
		conn, err := tls.Dial("tcp", ep, &tls.Config{
			MinVersion: k,
			MaxVersion: k,
		})
		if err != nil {
			res[v] = false
			continue
		}
		defer conn.Close()

		ver := conn.ConnectionState().Version
		if k == ver {
			res[v] = true
		}
	}

	return res, nil
}
