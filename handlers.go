package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Result struct {
	CanConnect   bool
	TLSProtocols map[string]bool
}

func RunCheck(w http.ResponseWriter, r *http.Request) {
	var res Result
	vars := mux.Vars(r)
	ep := vars["endpoint"]
	log.Printf("checking endpoint %s", ep)

	c, err := CheckConnection(ep)
	res.CanConnect = c
	if err != nil {
		log.Print(err)
	}

	t, err := CheckTLS(ep)
	if err != nil {
		log.Print(err)
	}
	res.TLSProtocols = t

	json.NewEncoder(w).Encode(res)
}
