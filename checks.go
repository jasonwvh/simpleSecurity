package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/jasonwvh/ocsp"
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

func CheckOCSPChain(ep string) (map[string]bool, error) {
	log.Printf("checking ocsp (%s)", ep)
	res := make(map[string]bool)

	conn, err := tls.Dial("tcp", ep, &tls.Config{})
	if err != nil {
		log.Printf("error dialing: %s", err)
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	for i := range certs {
		if i >= len(certs)-1 {
			break
		}

		revoked := isOCSPRevoked(certs[i], certs[i+1])
		res[certs[i].Subject.CommonName] = revoked
	}

	return res, nil
}

func isOCSPRevoked(issued, issuer *x509.Certificate) bool {
	ocspServer := issued.OCSPServer[0]

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(issued, issuer, opts)
	if err != nil {
		return false
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		return false
	}
	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		return false
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuer)
	if err != nil {
		return false
	}
	if ocspResponse.Status == ocsp.Revoked {
		log.Printf("certificate '%s' has been revoked by OCSP server %s, refusing connection", issued.Subject.CommonName, ocspServer)
		return true
	} else {
		return false
	}
}
