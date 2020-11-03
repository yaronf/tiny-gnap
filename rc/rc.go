package rc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"github.com/yaronf/tiny-gnap/common"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var rootLogger *zap.Logger
var log *zap.SugaredLogger

const NonceLength = 12

// type accessToken string

//func accessResource(rs) error {
//	var err1, err2 error
//	token, err1 := requestToken()
//	if err1 != nil {
//		return err1
//	}
//	request := makeRsRequest(token)
//	response, err2 := sendRequest(request)
//	if err2 != nil {
//		return err2
//	}
//}
//
//func requestToken() (accessToken, error) {
//	request := makeTokenRequest()
//	response := sendRequest(request)
//	return response.getToken(), nil
//}

func makeTokenRequest(resourceType string, actions []string, location string, client common.Client,
	redirectURI, redirectNonce string) common.Request {
	req := map[string]interface{}{
		"resources":    makeResources(resourceType, actions, location),
		"client":       makeClient(client.Name, client.URI, client.Pub, client.MessageSecurity),
		"interact":     makeInteract(redirectURI, redirectNonce),
		"capabilities": makeCapabilities(),
		"subject":      makeSubject(),
	}
	request := common.Request{req}
	return request
}

func makeSubject() interface{} {
	return map[string]interface{}{
		"sub_ids": []string{"iss-sub", "email"},
	}
}

func makeInteract(uri string, nonce string) interface{} {
	return map[string]interface{}{
		"redirect": true,
		"callback": map[string]string{
			"method": "redirect",
			"URI":    uri,
			"nonce":  nonce,
		},
	}
}

func makeClient(name string, uri string, clientKey jwk.Key, messageSecurity int) interface{} {
	var proof string
	switch messageSecurity {
	case common.DetachedSignature:
		proof = "jwsd"
	case common.AttachedJWS:
		proof = "jws"
	default:
		log.Fatal("Unsupported message security", messageSecurity)
	}
	key := map[string]interface{}{
		"proof": proof,
		"jwk":   clientKey,
	}
	return map[string]interface{}{
		"Name": name,
		"URI":  uri,
		"key":  key,
	}
}

func makeResources(resourceType string, actions []string, location string) interface{} {
	locations := []string{location} // TODO: multiple locations
	return map[string]interface{}{
		"type":      resourceType,
		"actions":   actions,
		"locations": locations,
	}
}

func makeCapabilities() interface{} {
	return make([]string, 0) // empty array (otherwise will be marshaled as null)
}

func runClient() {
	rootLogger, _ = zap.NewDevelopment()
	defer rootLogger.Sync() // flushes buffer, if any
	log = rootLogger.Sugar()

	client, err := initializeClientState()
	nonce, err := makeNonce()
	if err != nil {
		log.Fatal("Could not create nonce", err)
	}
	request := makeTokenRequest("photo-api", []string{"read", "print"}, "http://localhost/photos",
		client,
		"http://localhost/client/request-done",
		nonce)

	log.Debug("Created request", request.Dump())

	contentType, body, err := secureRequest(client, request)
	if err != nil {
		log.Fatal("Could not secure request", err)
	}

	err = sendRequest(client.ASURI, contentType, body)
	if err != nil {
		log.Fatal("Failed to send request: ", err)
	}
}

func initializeClientState() (common.Client, error) {
	home, _ := os.UserHomeDir()
	kvstore, err := skv.Open(home + common.CachePath)
	if err != nil {
		log.Fatal("Failed to open key-value store")
	}
	//goland:noinspection GoNilness
	defer kvstore.Close()

	var client common.Client
	const ClientID = "1"

	var name string
	prefix := "client." + ClientID + "."
	if //goland:noinspection GoNilness
	err := kvstore.Get(prefix+"Name", &name); err == skv.ErrNotFound {
		client = setupClient()
		err := saveClient(kvstore, prefix, client)
		if err != nil {
			log.Fatal("Could not store client in cache: ", err)
		}
	} else if err != nil {
		log.Fatal("Could not get client value: ", err)
	} else {
		client, err = common.LoadClient(kvstore, prefix, true)
		if err != nil {
			fmt.Println("Failed to load cached client", err)
		}
	}
	return client, err
}

func secureRequest(client common.Client, request common.Request) (contentType, body string, err error) {
	switch client.MessageSecurity {
	case common.AttachedJWS:
		body, err := signMessageAttached(request, client.Prv)
		if err != nil {
			return "", "", errors.Wrapf(err, "Could not sign message")
		}
		return "application/json", body, nil
	default:
		fmt.Println("Unsupported message security setting", client.MessageSecurity)
		return "", "", errors.New("Unsupported message security setting")
	}
}

func sendRequest(asUri, contentType, body string) error {
	resp, err := http.Post(asUri, contentType, strings.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "Could not send request to %s", asUri)
	}
	statusCode := resp.StatusCode
	if statusCode != 200 {
		log.Warn("Expected status code 200, got ", resp.StatusCode)
	}
	return nil
}

func saveClient(kvstore *skv.KVStore, prefix string, client common.Client) error {
	jsonPrv, err := json.Marshal(client.Prv)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal Prv")
	}
	jsonPub, err := json.Marshal(client.Pub)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal Pub")
	}
	multierr.AppendInto(&err, kvstore.Put(prefix+"Prv", string(jsonPrv)))
	multierr.AppendInto(&err, kvstore.Put(prefix+"Pub", string(jsonPub)))
	multierr.AppendInto(&err, kvstore.Put(prefix+"Name", client.Name))
	multierr.AppendInto(&err, kvstore.Put(prefix+"URI", client.URI))
	multierr.AppendInto(&err, kvstore.Put(prefix+"asUri", client.ASURI))
	multierr.AppendInto(&err, kvstore.Put(prefix+"MessageSecurity", client.MessageSecurity))

	return err
}

func signMessageAttached(request common.Request, key jwk.Key) (string, error) {
	asJSON, err := json.Marshal(request.Any)
	if err != nil {
		return "", errors.Wrapf(err, "Could not marshal request")
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, key.KeyID())
	_ = headers.Set(jws.AlgorithmKey, jwa.RS256)
	_ = headers.Set("htm", "post")
	_ = headers.Set("htu", "/tx")
	_ = headers.Set("ts", time.Now().Unix()) // Note all numbers will be decoded as float64 (a json package artifact)
	signed, err2 := jws.Sign(asJSON, jwa.RS256, key, jws.WithHeaders(headers))
	if err2 != nil {
		return "", errors.Wrapf(err, "Could not sign message body")
	}
	return string(signed), nil
}

func makeNonce() (string, error) {
	nonce := make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrapf(err, "Failed to create nonce")
	}
	return hex.EncodeToString(nonce), nil
}

func setupClient() common.Client {
	prv, pub, err := common.GenerateKeypair()
	if err != nil {
		log.Fatal("Cannot set up client", err)
	}
	c := common.Client{
		Name:            "My First Client",
		URI:             "http://localhost/client/clientID",
		Prv:             prv,
		Pub:             pub,
		MessageSecurity: common.AttachedJWS,
		ASURI:           "http://localhost:9090/tx",
	}
	return c
}
