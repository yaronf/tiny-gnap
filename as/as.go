package as

import (
	"../common"
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"os"
)

var rootLogger *zap.Logger
var logger *zap.SugaredLogger

type ClientInfo struct {
	pubKey jwk.Key
}

var clientInfo ClientInfo

func runServer() {
	rootLogger, _ = zap.NewProduction()
	defer rootLogger.Sync() // flushes buffer, if any
	logger = rootLogger.Sugar()

	loadClientInfo()

	http.HandleFunc("/tx", handleTx)
	err := http.ListenAndServe(":9090", nil)
	if err != nil {
		logger.Error("Could not start listener")
	}
}

// We cheat and read the client's public key from a cache shared with the client
func loadClientInfo() {
	home, _ := os.UserHomeDir()
	kvstore, err := skv.Open(home + common.CachePath)
	if err != nil {
		logger.Fatal("Failed to open key-value store: ", err)
	}
	defer kvstore.Close()

	var jsonPub string
	err = kvstore.Get("pub", &jsonPub)
	if err != nil {
		logger.Fatal("Could not read from cache: ", err)
	}
	pub, err := jwk.ParseKey([]byte(jsonPub))
	if err != nil {
		logger.Fatal("Could not parse pub: ", err)
	}
	clientInfo.pubKey = pub
	return
}

func handleTx(w http.ResponseWriter, r *http.Request) {
	logger.Infof("Received %s", r.Header.Get("content-type"))
	if handleRequest(r) != nil {
		w.WriteHeader(500)
	}
	w.WriteHeader(200) // TODO
}

func handleRequest(r *http.Request) error {
	contentType := r.Header.Get("content-type")
	if contentType == "application/json" { // attached JWS
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return errors.Wrapf(err, "Could not read body")
		}

		payload, err := verifyMessage(bodyBytes)
		if err != nil {
			return errors.Wrapf(err, "Could not verify request")
		}
		logger.Infof("Body verified: ", payload)
		return nil
	}
	return errors.New("Cannot handle content type: " + contentType)
}

func verifyMessage(body []byte) (payload []byte, err error) {
	var pubKey rsa.PublicKey
	err = clientInfo.pubKey.Raw(&pubKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to convert JWK to RSA public key")
	}
	payload, err = jws.Verify(body, jwa.RS256, pubKey) // TODO: hardcoded algorithm
	return
}
