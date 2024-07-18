package loader

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/certutil"
)

func NewDevLoader(certChannel chan *tls.Certificate, client bool, useSystemCertPool bool, interval time.Duration) (Loader, error) {
	l := &devLoader{
		certChannel: certChannel,
		client:      client,
		done:        make(chan bool),
		interval:    interval,
		caCertPool:  x509.NewCertPool(),
	}
	if useSystemCertPool {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
		l.caCertPool = systemCertPool
	}
	if !l.caCertPool.AppendCertsFromPEM(certutil.DefaultCACrt) {
		return nil, errors.Errorf("cannot append ca from default ca")
	}
	return l, nil
}

type devLoader struct {
	certChannel chan *tls.Certificate
	client      bool
	done        chan bool
	interval    time.Duration
	caCertPool  *x509.CertPool
}

func (d *devLoader) Close() error {
	d.done <- true
	close(d.done)
	close(d.certChannel)
	return nil
}

func (d *devLoader) Run() error {
	defaultCA, defaultCAPrivKey, err := certutil.CertificateKeyFromPEM(certutil.DefaultCACrt, certutil.DefaultCAKey, nil)
	if err != nil {
		return errors.Wrap(err, "cannot decode default ca certificate")
	}
	name := certutil.DefaultName

	for {
		certPEM, certPrivKeyPEM, err := certutil.CreateCertificate(
			d.client,
			!d.client,
			time.Duration(float64(d.interval)*1.1),
			defaultCA,
			defaultCAPrivKey,
			certutil.DefaultIPAddresses,
			certutil.DefaultDNSNames,
			nil,
			certutil.DefaultURIs,
			name,
			certutil.DefaultKeyType)
		if err != nil {
			return errors.Wrap(err, "cannot create server certificate")
		} else {
			serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
			if err != nil {
				return errors.Wrap(err, "cannot create server certificate from key pair")
			} else {
				d.certChannel <- &serverCert
			}
		}
		select {
		case <-d.done:
			return nil
		case <-time.After(d.interval):
		}
	}

	return nil
}

func (d *devLoader) GetCA() *x509.CertPool {
	return d.caCertPool
}

var _ Loader = (*devLoader)(nil)
