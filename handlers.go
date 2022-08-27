package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Result struct {
	CanConnect bool
}

func RunCheck(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ep := vars["endpoint"]
	log.Printf("checking endpoint %s", ep)

	c := CheckConnection(ep)
	res := &Result{
		CanConnect: c,
	}

	json.NewEncoder(w).Encode(res)
}
