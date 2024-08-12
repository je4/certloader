package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	configtrust "github.com/je4/trustutil/v2/pkg/config"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"os"
	"time"
)

type EnvConfig struct {
	Cert          string                    `json:"cert,omitempty" toml:"cert"`
	Key           string                    `json:"key,omitempty" toml:"key"`
	Interval      configutil.Duration       `json:"interval,omitempty" toml:"interval"`
	CA            []configtrust.Certificate `json:"ca,omitempty" toml:"ca"`
	UseSystemPool bool                      `json:"usesystempool,omitempty" toml:"usesystempool"`
}

func NewEnvLoader(certChannel chan *tls.Certificate, conf *EnvConfig, logger zLogger.ZLogger) (*EnvLoader, error) {
	if conf == nil {
		return nil, errors.New("env config missing")
	}
	var certPool *x509.CertPool
	var err error
	if conf.UseSystemPool || len(conf.CA) == 0 {
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
	} else {
		certPool = x509.NewCertPool()
	}
	for _, cert := range conf.CA {
		certPool.AddCert(cert.Certificate)
	}
	l := &EnvLoader{
		certChannel: certChannel,
		cert:        conf.Cert,
		key:         conf.Key,
		caCertPool:  certPool,
		interval:    time.Duration(conf.Interval),
		done:        make(chan bool),
		logger:      logger,
	}

	return l, nil
}

type EnvLoader struct {
	certChannel chan *tls.Certificate
	cert        string
	key         string
	certPEM     string
	keyPEM      string
	done        chan bool
	interval    time.Duration
	logger      zLogger.ZLogger
	caCertPool  *x509.CertPool
}

func (f *EnvLoader) GetCA() (*x509.CertPool, error) {
	return f.caCertPool, nil
}

func (f *EnvLoader) load() error {
	certPEM := os.Getenv(f.cert)
	if len(certPEM) == 0 {
		return errors.Errorf("certificate environment variable %s is empty", f.cert)
	}
	keyPEM := os.Getenv(f.key)
	if len(keyPEM) == 0 {
		return errors.Errorf("key environment variable %s is empty", f.key)
	}
	if f.certPEM == certPEM && f.keyPEM == keyPEM {
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return errors.Wrap(err, "cannot create x509 key pair")
	}
	f.certChannel <- &cert
	f.certPEM = certPEM
	f.keyPEM = keyPEM
	return nil
}

func (f *EnvLoader) Close() error {
	f.done <- true
	close(f.certChannel)
	return nil
}

func (f *EnvLoader) Run() error {
	for {
		if err := f.load(); err != nil {
			f.logger.Error().Err(err).Msg("cannot load")
		}
		select {
		case <-f.done:
			return nil
		case <-time.After(f.interval):
		}
	}
}

var _ Loader = (*EnvLoader)(nil)
