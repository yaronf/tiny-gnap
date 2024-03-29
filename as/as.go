package as

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"github.com/yaronf/tiny-gnap/common"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"time"
)

var rootLogger *zap.Logger
var log *zap.SugaredLogger

var client common.Client

var as common.AuthzServer

func runServer() {
	rootLogger, _ = zap.NewDevelopment()
	defer rootLogger.Sync() // flushes buffer, if any
	log = rootLogger.Sugar()

	var err error
	as, err = initializeASState()
	if err != nil {
		log.Fatal("Failed to initialize AS state")
	}

	err = loadClientInfo()
	if err != nil {
		log.Fatal("Failed to load client information")
	}

	// initialize non-standard configuration of jwx - read JSON numbers as strings to avoid conversion from/to floats
	jwx.DecoderSettings(jwx.WithUseNumber(true))

	http.HandleFunc("/tx", handleTx)
	err = http.ListenAndServe(":9090", nil)
	if err != nil {
		log.Error("Could not start listener")
	}
}

// We cheat and read the client's public key from a cache shared with the client
func loadClientInfo() error {
	kvstore, err := skv.Open(common.CachePath)
	if err != nil {
		return errors.Wrapf(err, "Failed to open key-value store: ")
	}
	defer kvstore.Close()

	client, err = common.LoadClient(kvstore, "client."+"1"+".", false)
	if err != nil {
		return errors.Wrapf(err, "Failed to load client")
	}
	return nil
}

func initializeASState() (common.AuthzServer, error) {
	kvstore, err := skv.Open(common.CachePath)
	if err != nil {
		log.Fatal("Failed to open key-value store")
	}
	//goland:noinspection GoNilness
	defer kvstore.Close()

	var as common.AuthzServer
	const ASID = "1"

	var name string
	prefix := "as." + ASID + "."
	if //goland:noinspection GoNilness
	err := kvstore.Get(prefix+"Name", &name); err == skv.ErrNotFound {
		as = setupAS()
		err := saveAS(kvstore, prefix, as)
		if err != nil {
			log.Fatal("Could not store client in cache: ", err)
		}
	} else if err != nil {
		log.Fatal("Could not get client value: ", err)
	} else {
		as, err = loadAS(kvstore, prefix, true)
		if err != nil {
			fmt.Println("Failed to load cached client", err)
		}
	}
	return as, err
}

func saveAS(kvstore *skv.KVStore, prefix string, as common.AuthzServer) error {
	jsonPrv, err := json.Marshal(as.Prv)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal Prv")
	}
	jsonPub, err := json.Marshal(as.Pub)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal Pub")
	}
	multierr.AppendInto(&err, kvstore.Put(prefix+"Prv", string(jsonPrv)))
	multierr.AppendInto(&err, kvstore.Put(prefix+"Pub", string(jsonPub)))
	multierr.AppendInto(&err, kvstore.Put(prefix+"Name", as.Name))
	multierr.AppendInto(&err, kvstore.Put(prefix+"URI", as.URI))
	return err
}

func loadAS(kvstore *skv.KVStore, prefix string, withPrivate bool) (common.AuthzServer, error) {
	var as common.AuthzServer
	var err error
	multierr.AppendInto(&err, kvstore.Get(prefix+"Name", &as.Name))
	multierr.AppendInto(&err, kvstore.Get(prefix+"URI", &as.URI))
	var jsonPub string
	multierr.AppendInto(&err, kvstore.Get(prefix+"Pub", &jsonPub))
	if err != nil {
		return as, errors.Wrapf(err, "Could not load AS properties")
	}
	var jsonPrv string
	if withPrivate {
		err := kvstore.Get(prefix+"Prv", &jsonPrv)
		if err != nil {
			return as, errors.Wrapf(err, "Could not load AS private key")
		}
		prv, err := jwk.ParseKey([]byte(jsonPrv))
		if err != nil {
			return as, errors.Wrapf(err, "Could not parse Prv")
		}
		as.Prv = prv
	}
	pub, err := jwk.ParseKey([]byte(jsonPub))
	if err != nil {
		return as, errors.Wrapf(err, "Could not parse Pub")
	}
	as.Pub = pub
	log.Debugf("Loaded AS %v", as)
	return as, nil
}

func setupAS() common.AuthzServer {
	prv, pub, err := common.GenerateKeypair()
	if err != nil {
		log.Fatal("Cannot set up client", err)
	}
	as := common.AuthzServer{
		Name: "My AS",
		URI:  "http://localhost/as/asID",
		Prv:  prv,
		Pub:  pub,
	}
	return as
}

func handleTx(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Received %s", r.Header.Get("content-type"))
	if r.Method != http.MethodPost {
		log.Error("Unsupported Tx method: ", r.Method)
		w.WriteHeader(500)
		return
	}
	log.Info("Received access request")
	if err := handleTxRequest(w, r); err != nil {
		log.Error("handleRequest failed: ", err)
		w.WriteHeader(500)
		return
	}
}

func handleTxRequest(w http.ResponseWriter, r *http.Request) error {
	contentType := r.Header.Get("content-type")
	if contentType != "application/json" { // attached JWS
		return errors.New("Cannot handle content type: " + contentType)
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.Wrapf(err, "Could not read body")
	}

	payload, err := verifyMessage(bodyBytes)
	if err != nil {
		return errors.Wrapf(err, "Could not verify request")
	}
	req, err := common.NewRequest(payload)
	if err != nil {
		return errors.Wrapf(err, "Could not parse request")
	}
	if !checkPolicy(req) {
		return errors.New("AS refused to grant AT")
	}
	accessToken, err := generateATForRequest(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to generate AT")
	}
	err = sendATResponse(w, accessToken)
	if err != nil {
		return errors.Wrapf(err, "Failed to send AT response")
	}
	return nil
}

func sendATResponse(w http.ResponseWriter, token string) error {
	response := map[string]interface{}{
		"access_token": map[string]interface{}{
			"value": token,
			"key":   false,
		},
	}
	asJson, err := json.Marshal(response)
	if err != nil {
		return errors.Wrapf(err, "Could not marshal response")
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(asJson)
	if err != nil {
		return errors.Wrapf(err, "Could not write response")
	}
	return nil
}

func generateATForRequest(req common.Request) (string, error) {
	const ATDuration = 3600
	token := jwt.New()
	reqMap, ok := req.Any.(map[string]interface{})
	if !ok {
		return "", errors.New("Bad request - not a map?")
	}
	var err error
	multierr.AppendInto(&err, token.Set("resources", reqMap["resources"]))
	multierr.AppendInto(&err, token.Set("client", reqMap["client"]))
	multierr.AppendInto(&err, token.Set(jwt.IssuedAtKey, time.Now().Unix()))
	multierr.AppendInto(&err, token.Set(jwt.ExpirationKey, time.Now().Unix()+ATDuration))
	multierr.AppendInto(&err, token.Set(jwt.IssuerKey, as.Name))
	if err != nil {
		return "", errors.Wrapf(err, "Could not populate token")
	}
	payload, err := jwt.Sign(token, jwa.RS256, as.Prv)
	if err != nil {
		return "", errors.Wrapf(err, "Could not sign token")
	}
	return string(payload), nil
}

func checkPolicy(req common.Request) bool {
	_ = req
	return true // TODO
}

func verifyMessage(body []byte) (payload []byte, err error) {
	err = validateJWSHeaders(body)
	if err != nil {
		return
	}
	payload, err = jws.VerifyWithJWK(body, client.Pub) // TODO: validate headers
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
	if err != nil || !isValidTimestamp(ts) {
		log.Debugf("ts: tsi %#v", tsi)
		return errors.New("Bad ts header")
	}

	return nil
}

func isValidTimestamp(ts int64) bool {
	const TimeSkew = 10 // sec
	now := time.Now().Unix()
	diff := ts - now
	log.Debugf("Timestamp ts %v now %v", ts, now)
	return diff > -TimeSkew && diff < TimeSkew
}
