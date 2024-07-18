package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/config"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/smallstep/certinfo"
	"io"
	"log"
	"strings"
	"time"
)

type Loader interface {
	io.Closer
	Run() error
	GetCA() *x509.CertPool
}

func initLoader(conf *config.TLSConfig, certChannel chan *tls.Certificate, client bool, logger zLogger.ZLogger) (l Loader, err error) {
	if conf.Interval == 0 {
		conf.Interval = configutil.Duration(time.Minute * 15)

	}
	switch strings.ToUpper(conf.Type) {
	case "ENV":
		l, err = NewEnvLoader(certChannel, client, conf.Cert, conf.Key, conf.CA, conf.UseSystemPool, time.Duration(conf.Interval), logger)
	case "FILE":
		l, err = NewFileLoader(certChannel, client, conf.Cert, conf.Key, conf.CA, conf.UseSystemPool, time.Duration(conf.Interval), logger)
	case "DEV":
		l, err = NewDevLoader(certChannel, client, conf.UseSystemPool, time.Duration(conf.Interval))
	default:
		err = errors.Errorf("unknown loader type %s", conf.Type)
		return
	}
	go func() {
		if logger != nil {
			logger.Info().Msg("starting loader")
		} else {
			log.Printf("starting loader\n")
		}
		if err := l.Run(); err != nil {
			if logger != nil {
				logger.Error().Err(err).Msg("error starting loader")
			} else {
				log.Printf("error starting loader: %v\n", err)
			}
		} else {
			if logger != nil {
				logger.Info().Msg("loader stopped")
			} else {
				log.Printf("loader stopped\n")
			}
		}
	}()
	return
}

func CreateServerLoader(mutual bool, conf *config.TLSConfig, uris []string, logger zLogger.ZLogger) (tlsConfig *tls.Config, l Loader, err error) {
	certChannel := make(chan *tls.Certificate)
	l, err = initLoader(conf, certChannel, false, logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create loader")
	}
	var cert *tls.Certificate
	select {
	case cert = <-certChannel:
		for _, cRaw := range cert.Certificate {
			c, err := x509.ParseCertificate(cRaw)
			if err != nil {
				return nil, nil, errors.Wrap(err, "cannot parse certificate")
			}
			if info, err := certinfo.CertificateText(c); err == nil {
				if logger != nil {
					logger.Debug().Msgf("server certificate loaded: %s", info)
				}
			} else {
				if logger != nil {
					logger.Debug().Msg("server certificate loaded")
				}
			}
		}
	case <-time.After(5 * time.Second):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	tlsConfig, err = tlsutil.CreateServerTLSConfig(*cert, mutual, uris, l.GetCA())
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigServerExchanger(tlsConfig, certChannel, logger); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}

func CreateClientLoader(conf *config.TLSConfig, logger zLogger.ZLogger, hosts ...string) (tlsConfig *tls.Config, l Loader, err error) {
	certChannel := make(chan *tls.Certificate)
	l, err = initLoader(conf, certChannel, true, logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create loader")
	}
	var cert *tls.Certificate
	select {
	case cert = <-certChannel:
		for _, cRaw := range cert.Certificate {
			c, err := x509.ParseCertificate(cRaw)
			if err != nil {
				return nil, nil, errors.Wrap(err, "cannot parse certificate")
			}
			if info, err := certinfo.CertificateText(c); err == nil {
				if logger != nil {
					logger.Debug().Msgf("client certificate loaded: %s", info)
				}
			} else {
				if logger != nil {
					logger.Debug().Msg("client certificate loaded")
				}
			}
		}
	case <-time.After(5 * time.Second):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	tlsConfig, err = tlsutil.CreateClientMTLSConfig(*cert, l.GetCA())
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigClientExchanger(tlsConfig, certChannel, logger); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}
