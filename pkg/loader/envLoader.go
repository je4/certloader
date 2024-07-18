package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"os"
	"time"
)

func NewEnvLoader(certChannel chan *tls.Certificate, client bool, cert, key string, ca []string, useSystemCertPool bool, interval time.Duration, logger zLogger.ZLogger) (*EnvLoader, error) {
	l := &EnvLoader{
		certChannel: certChannel,
		cert:        cert,
		key:         key,
		caCertPool:  x509.NewCertPool(),
		interval:    interval,
		done:        make(chan bool),
		logger:      logger,
	}
	if useSystemCertPool {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
		l.caCertPool = systemCertPool
	}
	for _, c := range ca {
		if !l.caCertPool.AppendCertsFromPEM([]byte(os.Getenv(c))) {
			return nil, errors.Errorf("cannot append ca from %s", c)
		}
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

func (f *EnvLoader) GetCA() *x509.CertPool {
	return f.caCertPool
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
