package loader

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/json"
	"github.com/je4/utils/v2/pkg/zLogger"
	"io"
	"net/http"
	"sync"
	"time"
)

func NewMiniVaultLoader(baseURL, parentToken string, tokenType string, tokenPolicies []string, tokenInterval time.Duration, certType string, uris, dnss []string, certInterval time.Duration, ca *x509.Certificate, logger zLogger.ZLogger) (*MiniVaultLoader, error) {
	l := &MiniVaultLoader{
		baseURL:       baseURL,
		certChannel:   make(chan *tls.Certificate),
		parentToken:   parentToken,
		tokenPolicies: tokenPolicies,
		certType:      certType,
		tokenType:     tokenType,
		uris:          uris,
		dnss:          dnss,
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
	tokenMutex    sync.Mutex
	client        *http.Client
	certChannel   chan *tls.Certificate
	caCertPool    *x509.CertPool
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
	certInterval  time.Duration
	logger        zLogger.ZLogger
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
	Renewable bool              `json:"renewable" example:"false"`
}

func (f *MiniVaultLoader) loadToken() (string, error) {
	if f.parentToken == "" {
		return "", errors.New("no parent token")
	}
	param := &TokenCreateStruct{
		Type:     f.tokenType,
		Policies: f.tokenPolicies,
		Meta:     map[string]string{},
		TTL:      f.tokenInterval.String(),
	}
	data, err := json.Marshal(param)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot marshal request")
	}
	req, err := http.NewRequest("POST", f.baseURL+"/token/create", bytes.NewBuffer(data))
	if err != nil {
		return "", errors.Wrap(err, "cannot create request")
	}
	req.Header.Set("X-Vault-Token", f.getToken(true))
	resp, err := f.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "cannot get token")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err != nil {
			return "", errors.Wrapf(err, "cannot get token: %s - %s", resp.Status, string(result))
		} else {
			return "", errors.Wrapf(err, "cannot get token: %s", resp.Status)
		}
	}
	var result string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", errors.Wrap(err, "cannot decode token")
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
	param := &CertCreateStruct{
		Type:     f.certType,
		URIs:     f.uris,
		DNSNames: f.dnss,
		TTL:      f.certInterval.String(),
	}
	data, err := json.Marshal(param)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot marshal request")
	}
	req, err := http.NewRequest("POST", f.baseURL+"/cert/create", bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "cannot create request")
	}
	req.Header.Set("X-Vault-Token", f.getToken(false))
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get cert")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err != nil {
			return nil, errors.Wrapf(err, "cannot get cert: %s - %s", resp.Status, string(result))
		} else {
			return nil, errors.Wrapf(err, "cannot get cert: %s", resp.Status)
		}
	}
	result := CertResultMessage{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "cannot decode cert")
	}
	cert, err := tls.X509KeyPair([]byte(result.Cert), []byte(result.Key))
	if err != nil {
		return nil, errors.Wrap(err, "cannot create x509 key pair")
	}
	return &cert, nil
}

func (f *MiniVaultLoader) Close() error {
	f.done <- true
	close(f.certChannel)
	return nil
}

func (f *MiniVaultLoader) Run() error {
	var tokenDone = make(chan bool)
	var certDone = make(chan bool)
	var wg = sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for { // token loop
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
	select {
	case <-f.done:
	}
	close(tokenDone)
	close(certDone)
	wg.Wait()
	return nil
}

func (f *MiniVaultLoader) GetCA() *x509.CertPool {
	req, err := http.NewRequest("GET", f.baseURL+"/cert/ca/pem", nil)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot create request")
		return nil
	}
	req.Header.Set("X-Vault-Token", f.token)
	resp, err := f.client.Do(req)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot get ca")
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err != nil {
			f.logger.Error().Msgf("cannot get ca: %s - %s", resp.Status, string(result))
		} else {
			f.logger.Error().Msgf("cannot get ca: %s", resp.Status)
		}
		return nil
	}
	result := CertResultMessage{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		f.logger.Error().Err(err).Msg("cannot decode ca")
		return nil
	}
	caCert, err := x509.ParseCertificate([]byte(result.CA))
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot parse ca")
		return nil
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	return caCertPool
}

var _ Loader = (*MiniVaultLoader)(nil)
