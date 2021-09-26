package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"ngrd.no/certd/api/client"
)

func main() {
	domainPtr := flag.String("domain", "", "Domain to fetch certificate for")

	certPtr := flag.String("cert", "server.crt", "Path to new certificate file")
	keyPtr := flag.String("key", "server.key", "Path to new private key file")
	bundlePtr := flag.String("bundle", "bundle.crt", "Path to new bundle certificate file")

	overwrite := flag.Bool("overwrite", false, "Overwrite existing files if they exist")

	certdServer := flag.String("certdserver", "localhost", "Hostname or IP of certd server")

	flag.Parse()

	if len(*domainPtr) == 0 {
		fmt.Fprintf(os.Stderr, "domain can't be empty string\n")
		os.Exit(1)
	}

	res, err := client.Get(*domainPtr, *certdServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed fetching certificate: %+v\n", err)
		os.Exit(1)
	}
	_ = res

	if fileExist(*certPtr) && !*overwrite {
		fmt.Fprintf(os.Stderr, "'%s' exist, won't overwrite\n", *certPtr)
		os.Exit(1)
	}
	crtBlock, _ := pem.Decode([]byte(res.Certificate))
	if err := ioutil.WriteFile(*certPtr, []byte(pem.EncodeToMemory(crtBlock)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed writing certificate file: %+v\n", err)
		os.Exit(1)
	}

	if fileExist(*keyPtr) && !*overwrite {
		fmt.Fprintf(os.Stderr, "'%s' exist, won't overwrite\n", *keyPtr)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(*keyPtr, []byte(res.PrivateKey), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed writing private key file: %+v\n", err)
		os.Exit(1)
	}

	if fileExist(*bundlePtr) && !*overwrite {
		fmt.Fprintf(os.Stderr, "'%s' exist, won't overwrite\n", *bundlePtr)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(*bundlePtr, []byte(res.Certificate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed writing certificate file: %+v\n", err)
		os.Exit(1)
	}
}

func fileExist(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}
