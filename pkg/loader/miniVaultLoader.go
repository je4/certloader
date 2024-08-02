package loader

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/json"
	vaultRest "github.com/je4/minivault/v2/pkg/rest"
	"github.com/je4/utils/v2/pkg/zLogger"
	"io"
	"net/http"
	"sync"
	"time"
)

func NewMiniVaultLoader(baseURL, token string, certType string, uris, dnss []string, tokenInterval, certInterval time.Duration, ca *x509.Certificate, logger zLogger.ZLogger) (*MiniVaultLoader, error) {
	l := &MiniVaultLoader{
		baseURL:       baseURL,
		certChannel:   make(chan *tls.Certificate),
		token:         token,
		certType:      certType,
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
	tokenInterval time.Duration
	certInterval  time.Duration
	logger        zLogger.ZLogger
	token         string
	baseURL       string
	certType      string
	uris          []string
	dnss          []string
}

func (f *MiniVaultLoader) setToken(token string) {
	f.tokenMutex.Lock()
	f.tokenMutex.Unlock()
	f.token = token
}

func (f *MiniVaultLoader) getToken() string {
	f.tokenMutex.Lock()
	f.tokenMutex.Unlock()
	return f.token
}

func (f *MiniVaultLoader) getCert() *tls.Certificate {
	param := &vaultRest.CertRequestMessage{}
	data, err := json.Marshal(param)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot marshal request")
	}
	req, err := http.NewRequest("POST", f.baseURL+"/cert/create", bytes.NewBuffer(data))
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot create request")
		return nil
	}
	req.Header.Set("X-Vault-Token", f.getToken())
	resp, err := f.client.Do(req)
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot get cert")
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err != nil {
			f.logger.Error().Msgf("cannot get cert: %s - %s", resp.Status, string(result))
		} else {
			f.logger.Error().Msgf("cannot get cert: %s", resp.Status)
		}
		return nil
	}
	result := vaultRest.CertResultMessage{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		f.logger.Error().Err(err).Msg("cannot decode cert")
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(result.Cert), []byte(result.Key))
	if err != nil {
		f.logger.Error().Err(err).Msg("cannot parse cert")
		return nil
	}
	return &cert
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
		for {
			select {
			case <-tokenDone:
				return
			case <-time.After(f.tokenInterval):
			}

		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-certDone:
				return
			case <-time.After(f.certInterval):
			}
		}
	}()
	select {
	case <-f.done:
	}
	close(tokenDone)
	close(certDone)
	wg.Wait()
	return nil
}

func (f *MiniVaultLoader) getCA() *x509.CertPool {
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
	result := vaultRest.CertResultMessage{}
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
