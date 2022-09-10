# SelfSigned

This is a very simple sign-signed certificate generator that gives no options except the dns name(s).

## Usage

```go
package main

import (
	"io/ioutil"

	"github.com/isaaguilar/selfsigned"
)

func main() {
    dnsName := []string{"foo.bar.svc.cluster.local", "foo.bar.svc", "foo.bar"}
	selfSignedCert := selfsigned.NewSelfSignedCertOrDie(dnsNames)

	ioutil.WriteFile("ca.crt", selfSignedCert.CACert, 0600)
	ioutil.WriteFile("tls.crt", selfSignedCert.TLSCert, 0600)
	ioutil.WriteFile("tls.key", selfSignedCert.TLSKey, 0600)
}
```
