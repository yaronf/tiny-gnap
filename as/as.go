package as

import (
	"github.com/yaronf/tiny-gnap/common"
	"encoding/json"
	"github.com/lestrrat-go/jwx"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var rootLogger *zap.Logger
var logger *zap.SugaredLogger

type ClientInfo struct {
	pubKey jwk.Key
}

var clientInfo ClientInfo

func runServer() {
	rootLogger, _ = zap.NewDevelopment()
	defer rootLogger.Sync() // flushes buffer, if any
	logger = rootLogger.Sugar()

	loadClientInfo()

	// initialize non-standard configuration of jwx - read JSON numbers as strings to avoid conversion from/to floats
	jwx.DecoderSettings(jwx.WithUseNumber(true))

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
	logger.Debugf("Received %s", r.Header.Get("content-type"))
	if r.Method != http.MethodPost {
		logger.Error("Unsupported Tx method: ", r.Method)
		w.WriteHeader(500)
		return
	}
	if err := handleTxRequest(r); err != nil {
		logger.Error("handleRequest failed: ", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200) // TODO
}

func handleTxRequest(r *http.Request) error {
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
		_ = payload // TODO
		return nil
	}
	return errors.New("Cannot handle content type: " + contentType)
}

func verifyMessage(body []byte) (payload []byte, err error) {
	err = validateJWSHeaders(body)
	if err != nil {
		return
	}
	payload, err = jws.VerifyWithJWK(body, clientInfo.pubKey) // TODO: validate headers
	return
}

func validateJWSHeaders(body []byte) error {
	message, err := jws.ParseString(string(body))
	if err != nil || message == nil {
		return errors.Wrapf(err, "Failed to parse JWS")
	}
	if len(message.Signatures()) != 1 {
		return errors.New("Badly formatted JWS")
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	if headers == nil {
		return errors.New("Cannot find headers")
	}
	htm, found := headers.Get("htm")
	if !found || htm != "post" {
		return errors.New("Bad htm header")
	}
	htu, found := headers.Get("htu")
	if !found || htu != "/tx" { // TODO hardcoded
		return errors.New("Bad htu header")
	}
	tsi, found := headers.Get("ts") // read as json.Number
	tsn, ok := tsi.(json.Number)
	if !found || !ok {
		return errors.New("Expected a json.Number for ts, no luck")
	}
	ts, err := tsn.Int64()
	if err != nil || !isValidTimestamp(int64(ts)) {
		logger.Debugf("ts: tsi %#v", tsi)
		return errors.New("Bad ts header")
	}

	return nil
}

func isValidTimestamp(ts int64) bool {
	const TimeSkew = 10 // sec
	now := time.Now().Unix()
	diff := ts - now
	logger.Debugf("Timestamp ts %v now %v", ts, now)
	return diff > -TimeSkew && diff < TimeSkew
}
