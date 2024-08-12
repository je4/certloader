package loader

import (
	"crypto/tls"
	"crypto/x509"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"time"

	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/certutil"
)

type DevConfig struct {
	Interval      configutil.Duration `json:"interval,omitempty" toml:"interval"`
	UseSystemPool bool                `json:"usesystempool,omitempty" toml:"usesystempool"`
}

func NewDevLoader(certChannel chan *tls.Certificate, client bool, conf *DevConfig, logger zLogger.ZLogger) (Loader, error) {
	if conf == nil {
		conf = &DevConfig{
			Interval: configutil.Duration(time.Minute * 10),
		}
	}
	var certPool *x509.CertPool
	var err error
	if conf.UseSystemPool {
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
	} else {
		certPool = x509.NewCertPool()
	}
	certPool.AppendCertsFromPEM(certutil.DefaultCACrt)
	l := &devLoader{
		certChannel: certChannel,
		client:      client,
		done:        make(chan bool),
		interval:    time.Duration(conf.Interval),
		caCertPool:  certPool,
		logger:      logger,
	}
	return l, nil
}

type devLoader struct {
	certChannel chan *tls.Certificate
	client      bool
	done        chan bool
	interval    time.Duration
	caCertPool  *x509.CertPool
	logger      zLogger.ZLogger
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

func (d *devLoader) GetCA() (*x509.CertPool, error) {
	return d.caCertPool, nil
}

var _ Loader = (*devLoader)(nil)
