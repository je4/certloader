package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	configtrust "github.com/je4/trustutil/v2/pkg/config"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/smallstep/certinfo"
	"io"
	"log"
	"strings"
	"time"
)

type MiniVaultConfig struct {
	BaseURL       string                    `json:"baseurl,omitempty" toml:"baseurl"`
	ParentToken   string                    `json:"parenttoken,omitempty" toml:"parenttoken"`
	TokenType     string                    `json:"tokentype,omitempty" toml:"tokentype"`
	TokenPolicies []string                  `json:"tokenpolicies,omitempty" toml:"tokenpolicies"`
	TokenInterval configutil.Duration       `json:"tokeninterval,omitempty" toml:"tokeninterval"`
	CertType      string                    `json:"certtype,omitempty" toml:"certtype"`
	URIs          []string                  `json:"uris,omitempty" toml:"uris"`
	DNSs          []string                  `json:"dnss,omitempty" toml:"dnss"`
	CertInterval  configutil.Duration       `json:"certinterval,omitempty" toml:"certinterval"`
	Certificates  []configtrust.Certificate `json:"certificates,omitempty" toml:"certificates"`
	CA            []configtrust.Certificate `json:"ca,omitempty" toml:"ca"`
	UseSystemPool bool                      `json:"usesystempool,omitempty" toml:"usesystempool"`
}

type FileConfig struct {
	Cert string `json:"cert,omitempty" toml:"cert"`
	Key  string `json:"key,omitempty" toml:"key"`
}

type EnvConfig struct {
	Cert string `json:"cert,omitempty" toml:"cert"`
	Key  string `json:"key,omitempty" toml:"key"`
}

type Config struct {
	Type          string                    `json:"type,omitempty" toml:"type"` // "ENV", "FILE", "SERVICE" OR "SELF"
	Interval      configutil.Duration       `json:"interval,omitempty" toml:"interval"`
	Vault         *MiniVaultConfig          `json:"minivault,omitempty" toml:"minivault"`
	File          *FileConfig               `json:"file,omitempty" toml:"file"`
	Env           *EnvConfig                `json:"env,omitempty" toml:"env"`
	CA            []configtrust.Certificate `json:"ca,omitempty" toml:"ca"`
	UseSystemPool bool                      `json:"usesystempool,omitempty" toml:"usesystempool"`
}

type Loader interface {
	io.Closer
	Run() error
	GetCA() *x509.CertPool
}

func initLoader(conf *Config, certChannel chan *tls.Certificate, client bool, logger zLogger.ZLogger) (l Loader, err error) {
	if conf.Interval == 0 {
		conf.Interval = configutil.Duration(time.Minute * 15)
	}
	var certPool *x509.CertPool
	if len(conf.CA) == 0 || conf.UseSystemPool {
		certPool, err = x509.SystemCertPool()
	} else {
		certPool = x509.NewCertPool()
	}
	for _, cert := range conf.CA {
		certPool.AddCert(cert.Certificate)
	}
	switch strings.ToUpper(conf.Type) {
	case "ENV":
		if conf.Env == nil {
			err = errors.New("env config missing")
			return
		}
		l, err = NewEnvLoader(certChannel, client, conf.Env.Cert, conf.Env.Key, certPool, time.Duration(conf.Interval), logger)
	case "FILE":
		if conf.File == nil {
			err = errors.New("file config missing")
			return
		}
		l, err = NewFileLoader(certChannel, client, conf.File.Cert, conf.File.Key, certPool, time.Duration(conf.Interval), logger)
	case "DEV":
		l, err = NewDevLoader(certChannel, client, conf.UseSystemPool, time.Duration(conf.Interval))
	case "MINIVAULT":
		vaultConf := conf.Vault
		if vaultConf == nil {
			err = errors.New("minivault config missing")
			return
		}
		var vaultCertPool *x509.CertPool
		if len(vaultConf.CA) == 0 || conf.UseSystemPool {
			vaultCertPool, err = x509.SystemCertPool()
		} else {
			vaultCertPool = x509.NewCertPool()
		}
		for _, cert := range vaultConf.CA {
			vaultCertPool.AddCert(cert.Certificate)
		}
		l, err = NewMiniVaultLoader(
			vaultConf.BaseURL,
			vaultConf.ParentToken,
			vaultConf.TokenType,
			vaultConf.TokenPolicies,
			time.Duration(vaultConf.TokenInterval),
			vaultConf.CertType,
			vaultConf.URIs,
			vaultConf.DNSs,
			time.Duration(vaultConf.CertInterval),
			vaultCertPool,
			logger)
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

func CreateServerLoader(mutual bool, conf *Config, uris []string, logger zLogger.ZLogger) (tlsConfig *tls.Config, l Loader, err error) {
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

func CreateClientLoader(conf *Config, logger zLogger.ZLogger, hosts ...string) (tlsConfig *tls.Config, l Loader, err error) {
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
