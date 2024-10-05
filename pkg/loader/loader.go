package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/rs/zerolog"
	"github.com/smallstep/certinfo"
	"io"
	"os"
	"strings"
	"time"
)

type Config struct {
	Type string `json:"type,omitempty" toml:"type"` // "ENV", "FILE", "SERVICE" OR "SELF"
	//Interval       configutil.Duration       `json:"interval,omitempty" toml:"interval"`
	Vault *MiniVaultConfig `json:"minivault,omitempty" toml:"minivault"`
	File  *FileConfig      `json:"file,omitempty" toml:"file"`
	Env   *EnvConfig       `json:"env,omitempty" toml:"env"`
	Dev   *DevConfig       `json:"dev,omitempty" toml:"dev"`
	ACME  *ACMEConfig      `json:"acme,omitempty" toml:"acme"`
	//CA             []configtrust.Certificate `json:"ca,omitempty" toml:"ca"`
	//UseSystemPool  bool                `json:"usesystempool,omitempty" toml:"usesystempool"`
	InitialTimeout configutil.Duration `json:"initialtimeout,omitempty" toml:"initialtimeout"`
}

var noTLSConfig = errors.New("no tls config")

type Loader interface {
	io.Closer
	Run() error
	GetCA() (*x509.CertPool, error)
	GetTLSConfig() (*tls.Config, error)
}

func initLoader(conf *Config, certChannel chan *tls.Certificate, client bool, logger zLogger.ZLogger) (l Loader, err error) {
	if logger == nil {
		l := zerolog.New(os.Stderr).With().Timestamp().Logger()
		logger = &l
	}
	switch strings.ToUpper(conf.Type) {
	case "ENV":
		l, err = NewEnvLoader(certChannel, conf.Env, logger)
	case "FILE":
		l, err = NewFileLoader(certChannel, conf.File, logger)
	case "DEV":
		l, err = NewDevLoader(certChannel, client, conf.Dev, logger)
	case "ACME":
		l, err = NewACMELoader(certChannel, conf.ACME)
	case "MINIVAULT":
		l, err = NewMiniVaultLoader(
			certChannel,
			conf.Vault,
			logger)
	default:
		err = errors.Errorf("unknown loader type %s", conf.Type)
		return
	}
	go func() {
		logger.Info().Msg("starting loader")
		if err := l.Run(); err != nil {
			logger.Error().Err(err).Msg("error starting loader")
		} else {
			logger.Info().Msg("loader stopped")
		}
	}()
	return
}

func CreateServerLoader(mutual bool, conf *Config, uris []string, logger zLogger.ZLogger) (tlsConfig *tls.Config, l Loader, err error) {
	if conf.InitialTimeout == 0 {
		conf.InitialTimeout = configutil.Duration(time.Minute)
	}
	certChannel := make(chan *tls.Certificate)
	l, err = initLoader(conf, certChannel, false, logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create loader")
	}
	if cert, err := l.GetTLSConfig(); err == nil {
		return cert, l, nil
	} else {
		if !errors.Is(err, noTLSConfig) {
			return nil, nil, errors.Wrap(err, "cannot get tls config")
		}
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
	case <-time.After(time.Duration(conf.InitialTimeout)):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	// after getting a certificate there should be no problem getting die CA
	ca, err := l.GetCA()
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot get ca")
	}
	tlsConfig, err = tlsutil.CreateServerTLSConfig(*cert, mutual, uris, ca)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigServerExchanger(tlsConfig, certChannel, logger); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}

func CreateClientLoader(conf *Config, logger zLogger.ZLogger, hosts ...string) (tlsConfig *tls.Config, l Loader, err error) {
	if conf.InitialTimeout == 0 {
		conf.InitialTimeout = configutil.Duration(time.Minute)
	}
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
	case <-time.After(time.Duration(conf.InitialTimeout)):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	ca, err := l.GetCA()
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot get ca")
	}
	tlsConfig, err = tlsutil.CreateClientMTLSConfig(*cert, ca)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigClientExchanger(tlsConfig, certChannel, logger); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}
