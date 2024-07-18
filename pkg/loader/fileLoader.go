package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"os"
	"time"
)

func NewFileLoader(certChannel chan *tls.Certificate, client bool, cert, key string, ca []string, useSystemCertPool bool, interval time.Duration, logger zLogger.ZLogger) (*FileLoader, error) {
	l := &FileLoader{
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
	for _, caName := range ca {
		pemData, err := os.ReadFile(caName)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read ca file %s", ca)
		}
		if !l.caCertPool.AppendCertsFromPEM(pemData) {
			return nil, errors.Errorf("cannot append ca from %s", caName)
		}
	}

	return l, nil
}

type FileLoader struct {
	certChannel chan *tls.Certificate
	cert        string
	key         string
	caCertPool  *x509.CertPool
	lastCheck   time.Time
	done        chan bool
	interval    time.Duration
	logger      zLogger.ZLogger
}

func (f *FileLoader) GetCA() *x509.CertPool {
	return f.caCertPool
}

func (f *FileLoader) isNew() (bool, error) {
	certStat, err := os.Stat(f.cert)
	if err != nil {
		return false, errors.Wrapf(err, "cannot stat %s", f.cert)
	}
	keyStat, err := os.Stat(f.key)
	if err != nil {
		return false, errors.Wrapf(err, "cannot stat %s", f.key)
	}
	if certStat.ModTime().After(f.lastCheck) || keyStat.ModTime().After(f.lastCheck) {
		return true, nil
	}
	return false, nil
}

func (f *FileLoader) load() error {
	now := time.Now()
	certPEM, err := os.ReadFile(f.cert)
	if err != nil {
		return errors.Wrapf(err, "cannot read certificate file %s", f.cert)
	}
	keyPEM, err := os.ReadFile(f.key)
	if err != nil {
		return errors.Wrapf(err, "cannot read key file %s", f.key)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.Wrap(err, "cannot create x509 key pair")
	}
	f.lastCheck = now
	f.certChannel <- &cert
	return nil
}

func (f *FileLoader) Close() error {
	f.done <- true
	close(f.certChannel)
	return nil
}

func (f *FileLoader) Run() error {
	for {
		isNew, err := f.isNew()
		if err != nil {
			f.logger.Error().Err(err).Msg("cannot check if new")
		} else if isNew {
			err = f.load()
			if err != nil {
				f.logger.Error().Err(err).Msg("cannot load")
			}
		}
		select {
		case <-f.done:
			return nil
		case <-time.After(f.interval):
		}
	}
}

var _ Loader = (*FileLoader)(nil)
