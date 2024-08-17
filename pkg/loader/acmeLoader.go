package loader

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/crypto/acme/autocert"
)

type ACMEConfig struct {
	CacheFolder   string   `json:"cachefolder,omitempty" toml:"cachefolder"`
	Email         string   `json:"email,omitempty" toml:"email"`
	HostWhitelist []string `json:"hostwhitelist,omitempty" toml:"hostwhitelist"`
}

func NewACMELoader(_ chan *tls.Certificate, conf *ACMEConfig) (*ACMELoader, error) {
	al := &ACMELoader{
		certManager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(conf.CacheFolder),
			Email:  conf.Email,
		},
		done: make(chan bool),
	}
	if len(conf.HostWhitelist) > 0 {
		al.certManager.HostPolicy = autocert.HostWhitelist(conf.HostWhitelist...)
	}
	return al, nil
}

type ACMELoader struct {
	certManager *autocert.Manager
	done        chan bool
}

func (al *ACMELoader) GetTLSConfig() (*tls.Config, error) {
	return al.certManager.TLSConfig(), nil
}

func (al *ACMELoader) Close() error {
	al.done <- true
	close(al.done)
	return nil
}

func (al *ACMELoader) Run() error {
	<-al.done
	return nil
}

func (al ACMELoader) GetCA() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}

var _ Loader = (*ACMELoader)(nil)
