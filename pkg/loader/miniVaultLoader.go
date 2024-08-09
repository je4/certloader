package loader

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/minivault/v2/pkg/cert"
	vaultClient "github.com/je4/minivault/v2/pkg/client"
	"github.com/je4/minivault/v2/pkg/token"
	"github.com/je4/utils/v2/pkg/zLogger"
	"sync"
	"time"
)

func NewMiniVaultLoader(
	certChannel chan *tls.Certificate,
	baseURL, parentToken, tokenType string,
	tokenPolicies []string,
	tokenInterval, tokenTTL time.Duration,
	certType string,
	uris, dnss, ips []string,
	certInterval, certTTL time.Duration,
	vaultCertPool *x509.CertPool,
	logger zLogger.ZLogger,
) (*MiniVaultLoader, error) {
	l := &MiniVaultLoader{
		vaultClient:   vaultClient.NewClient(baseURL, vaultCertPool),
		baseURL:       baseURL,
		certChannel:   certChannel,
		parentToken:   parentToken,
		tokenPolicies: tokenPolicies,
		certType:      certType,
		tokenType:     tokenType,
		uris:          uris,
		dnss:          dnss,
		ips:           ips,
		certInterval:  certInterval,
		certTTL:       certTTL,
		tokenInterval: tokenInterval,
		tokenTTL:      tokenTTL,
		vaultCertPool: vaultCertPool,
		done:          make(chan bool),
		logger:        logger,
	}
	/*
		l.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: l.vaultCertPool,
				},
			},
		}

	*/
	return l, nil
}

type MiniVaultLoader struct {
	tokenMutex sync.Mutex
	//	client        *http.Client
	vaultClient   *vaultClient.Client
	certChannel   chan *tls.Certificate
	lastCheck     time.Time
	done          chan bool
	baseURL       string
	parentToken   string
	token         string
	tokenType     string
	tokenPolicies []string
	tokenInterval time.Duration
	certType      string
	uris          []string
	dnss          []string
	ips           []string
	certInterval  time.Duration
	logger        zLogger.ZLogger
	vaultCertPool *x509.CertPool
	certTTL       time.Duration
	tokenTTL      time.Duration
}

func (f *MiniVaultLoader) setToken(token string, parent bool) {
	f.tokenMutex.Lock()
	f.tokenMutex.Unlock()
	if parent {
		f.parentToken = token
	} else {
		f.token = token
	}
}

func (f *MiniVaultLoader) getToken(parent bool) string {
	f.tokenMutex.Lock()
	f.tokenMutex.Unlock()
	if parent {
		return f.parentToken
	} else {
		return f.token
	}
}

type TokenCreateStruct struct {
	Type      string            `json:"type" example:"client_cert"`
	Policies  []string          `json:"Policies" example:"policy1,policy2"`
	Meta      map[string]string `json:"meta" example:"key1:value1,key2:value2"`
	TTL       string            `json:"ttl" example:"1h"`
	MaxTTL    string            `json:"maxttl" example:"3h"`
	Renewable bool              `json:"renewable" example:"false"`
}

func (f *MiniVaultLoader) loadToken() (string, error) {
	if f.parentToken == "" {
		return "", errors.New("no parent token")
	}
	param := &token.CreateStruct{
		Type:     f.tokenType,
		Policies: f.tokenPolicies,
		Meta:     map[string]string{},
		TTL:      f.tokenTTL.String(),
	}
	result, err := f.vaultClient.CreateToken(f.parentToken, param)
	if err != nil {
		return "", errors.Wrap(err, "cannot get token")
	}
	return result, nil
}

type CertCreateStruct struct {
	Type     string   `json:"type" example:"client_cert"`
	URIs     []string `json:"uris" example:"uri1,uri2"`
	DNSNames []string `json:"dnnames" example:"dns1,dns2"`
	TTL      string   `json:"ttl" example:"1h"`
}

type CertResultMessage struct {
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
	CA   string `json:"ca,omitempty"`
}

func (f *MiniVaultLoader) loadCert() (*tls.Certificate, error) {
	if f.token == "" {
		return nil, errors.New("no token")
	}
	param := &cert.CreateStruct{
		Type:     f.certType,
		URIs:     f.uris,
		DNSNames: f.dnss,
		IPs:      f.ips,
		TTL:      f.certTTL.String(),
	}
	result, err := f.vaultClient.CreateCert(f.token, param)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get cert")
	}
	return result.Cert, nil
}

func (f *MiniVaultLoader) GetCA() (*x509.CertPool, error) {
	pool, err := f.vaultClient.GetCA()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get ca")
	}
	return pool, nil
}

func (f *MiniVaultLoader) Close() error {
	f.done <- true
	close(f.certChannel)
	return nil
}

func (f *MiniVaultLoader) Run() error {
	var tokenDone = make(chan bool)
	var certDone = make(chan bool)

	for { // token retry loop
		if token, err := f.loadToken(); err == nil {
			f.setToken(token, false)
			break
		} else {
			f.logger.Error().Err(err).Msg("cannot get token")
			f.logger.Info().Msg("token sleeping 10s")
			select {
			case <-tokenDone:
				return nil
			case <-time.After(10 * time.Second):
			}
		}
	} // end token retry loop
	for { // cert retry loop
		if cert, err := f.loadCert(); err == nil {
			f.certChannel <- cert
			break
		} else {
			f.logger.Error().Err(err).Msg("cannot get cert")
			f.logger.Info().Msg("cert sleeping 10s")
			select {
			case <-certDone:
				return nil
			case <-time.After(10 * time.Second):
			}
		}
	} // end cert retry loop

	var wg = sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for { // cert loop
			f.logger.Info().Msgf("cert sleeping %s", f.certInterval.String())
			select {
			case <-certDone:
				return
			case <-time.After(f.certInterval):
				for { // cert retry loop
					if cert, err := f.loadCert(); err == nil {
						f.certChannel <- cert
						break
					} else {
						f.logger.Error().Err(err).Msg("cannot get cert")
						f.logger.Info().Msg("cert sleeping 10s")
						select {
						case <-certDone:
							return
						case <-time.After(10 * time.Second):
						}
					}
				} // end cert retry loop
			}
		} // end cert loop
	}()
	go func() {
		defer wg.Done()
		for { // token loop
			f.logger.Info().Msgf("token sleeping %s", f.tokenInterval.String())
			select {
			case <-tokenDone:
				return
			case <-time.After(f.tokenInterval):
				for { // token retry loop
					if token, err := f.loadToken(); err == nil {
						f.setToken(token, false)
						break
					} else {
						f.logger.Error().Err(err).Msg("cannot get token")
						f.logger.Info().Msg("token sleeping 10s")
						select {
						case <-tokenDone:
							return
						case <-time.After(10 * time.Second):
						}
					}
				} // end token retry loop
			}
		} // end token loop
	}()
	select {
	case <-f.done:
	}
	close(tokenDone)
	close(certDone)
	wg.Wait()
	return nil
}

var _ Loader = (*MiniVaultLoader)(nil)
