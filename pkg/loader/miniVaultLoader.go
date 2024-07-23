package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"net/http"
	"time"
)

func NewMiniVaultLoader(baseURL, token string, tokenInterval, certInterval time.Duration, ca *x509.Certificate, logger zLogger.ZLogger) (*MiniVaultLoader, error) {
	l := &MiniVaultLoader{
		baseURL:       baseURL,
		certChannel:   make(chan *tls.Certificate),
		token:         token,
		certInterval:  certInterval,
		tokenInterval: tokenInterval,
		done:          make(chan bool),
		logger:        logger,
	}
	if ca != nil {
		l.caCertPool = x509.NewCertPool()
		l.caCertPool.AddCert(ca)
	} else {
		var err error
		l.caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
	}
	l.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: l.caCertPool,
			},
		},
	}
	return l, nil
}

type MiniVaultLoader struct {
	client        *http.Client
	certChannel   chan *tls.Certificate
	caCertPool    *x509.CertPool
	lastCheck     time.Time
	done          chan bool
	tokenInterval time.Duration
	certInterval  time.Duration
	logger        zLogger.ZLogger
	token         string
	baseURL       string
}

func (f *MiniVaultLoader) GetCA() *x509.CertPool {
	f.client.Get(f.baseURL + "/cert/ca/pem")
}
