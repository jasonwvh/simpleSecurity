package main

import (
	"crypto/tls"
	"log"
)

func CheckConnection(ep string) bool {
	log.Printf("establishing conection to %s", ep)

	conn, err := tls.Dial("tcp", ep, &tls.Config{})
	if err != nil {
		log.Print(err)
		return false
	}
	log.Printf("connection established to %s", conn.RemoteAddr().String())
	return true
}
