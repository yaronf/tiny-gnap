package rc

import (
	"../common"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var rootLogger *zap.Logger
var logger *zap.SugaredLogger

const NonceLength = 12

// type accessToken string

type Any interface{}

type Request struct {
	Any
} // the raw JSON structure

type Client struct {
	name, uri       string
	prv, pub        jwk.Key
	messageSecurity int
	asURI           string
}

func (req Request) dump() string {
	var buff bytes.Buffer
	_ = json.Indent(&buff, []byte(req.toJSON()), "", "  ")
	return buff.String()
}

func (req Request) toJSON() string {
	s, err := json.Marshal(req.Any)
	if err != nil {
		logger.Fatal("Could not marshal request: ", err)
	}
	return string(s)
}

func generateClientKey() (prv, pub jwk.Key, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate RSA key", err)
		return nil, nil, err
	}
	prv, err = jwk.New(privateKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to create private key")
	}
	pub, err = jwk.New(privateKey.Public())
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to create public key")
	}
	err = jwk.AssignKeyID(prv)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to assign key ID to prv")
	}
	err = jwk.AssignKeyID(pub)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to assign key ID to pub")
	}
	return
}

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

func makeTokenRequest(resourceType string, actions []string, location string, client Client,
	redirectURI, redirectNonce string) Request {
	req := map[string]interface{}{
		"resources":    makeResources(resourceType, actions, location),
		"client":       makeClient(client.name, client.uri, client.pub, client.messageSecurity),
		"interact":     makeInteract(redirectURI, redirectNonce),
		"capabilities": makeCapabilities(),
		"subject":      makeSubject(),
	}
	request := Request{req}
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
			"uri":    uri,
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
		logger.Fatal("Unsupported message security", messageSecurity)
	}
	key := map[string]interface{}{
		"proof": proof,
		"jwk":   clientKey,
	}
	return map[string]interface{}{
		"name": name,
		"uri":  uri,
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
	rootLogger, _ = zap.NewProduction()
	defer rootLogger.Sync() // flushes buffer, if any
	logger = rootLogger.Sugar()

	err, client := initializeClientState()
	nonce, err := makeNonce()
	if err != nil {
		logger.Fatal("Could not create nonce", err)
	}
	request := makeTokenRequest("photo-api", []string{"read", "print"}, "http://localhost/photos",
		client,
		"http://localhost/client/request-done",
		nonce)

	logger.Debug("Created request", request.dump())

	contentType, body, err := secureRequest(client, request)
	if err != nil {
		logger.Fatal("Could not secure request", err)
	}

	err = sendRequest(client.asURI, contentType, body)
	if err != nil {
		logger.Fatal("Failed to send request: ", err)
	}
}

func initializeClientState() (error, Client) {
	home, _ := os.UserHomeDir()
	kvstore, err := skv.Open(home + common.CachePath)
	if err != nil {
		logger.Fatal("Failed to open key-value store")
	}
	defer kvstore.Close()

	var client Client

	var name string
	if err := kvstore.Get("name", &name); err == skv.ErrNotFound {
		client = setupClient()
		err := saveClient(kvstore, client)
		if err != nil {
			logger.Fatal("Could not store client in cache: ", err)
		}
	} else if err != nil {
		logger.Fatal("Could not get client value: ", err)
	} else {
		client, err = loadClient(kvstore)
		if err != nil {
			fmt.Println("Failed to load cached client", err)
		}
	}
	return err, client
}

func secureRequest(client Client, request Request) (contentType, body string, err error) {
	switch client.messageSecurity {
	case common.AttachedJWS:
		body, err := signMessageAttached(request, client.prv)
		if err != nil {
			return "", "", errors.Wrapf(err, "Could not sign message")
		}
		return "application/json", body, nil
	default:
		fmt.Println("Unsupported message security setting", client.messageSecurity)
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
		logger.Warn("Expected status code 200, got ", resp.StatusCode)
	}
	return nil
}

func saveClient(kvstore *skv.KVStore, client Client) error {
	kvstore.Put("name", client.name)
	kvstore.Put("uri", client.uri)
	kvstore.Put("asUri", client.asURI)
	kvstore.Put("messageSecurity", client.messageSecurity)
	jsonPrv, err := json.Marshal(client.prv)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal prv")
	}
	kvstore.Put("prv", string(jsonPrv))
	jsonPub, err := json.Marshal(client.pub)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal pub")
	}
	kvstore.Put("pub", string(jsonPub))

	return nil
}

func loadClient(kvstore *skv.KVStore) (Client, error) {
	var client Client
	kvstore.Get("name", &client.name)
	kvstore.Get("uri", &client.uri)
	kvstore.Get("asUri", &client.asURI)
	kvstore.Get("messageSecurity", &client.messageSecurity)
	var jsonPrv, jsonPub string
	kvstore.Get("prv", &jsonPrv)
	kvstore.Get("pub", &jsonPub)
	prv, err := jwk.ParseKey([]byte(jsonPrv))
	if err != nil {
		return client, errors.Wrapf(err, "Could not parse prv")
	}
	client.prv = prv
	pub, err := jwk.ParseKey([]byte(jsonPub))
	if err != nil {
		return client, errors.Wrapf(err, "Could not parse pub")
	}
	client.pub = pub
	logger.Infof("Loaded client %v", client)
	return client, nil
}

func signMessageAttached(request Request, key jwk.Key) (string, error) {
	asJSON, err := json.Marshal(request.Any)
	if err != nil {
		return "", errors.Wrapf(err, "Could not marshal request")
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, key.KeyID())
	_ = headers.Set(jws.AlgorithmKey, jwa.RS256)
	_ = headers.Set("htm", "post")
	_ = headers.Set("htu", "/tx")
	_ = headers.Set("ts", time.Now().Unix())
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

func setupClient() Client {
	prv, pub, err := generateClientKey()
	if err != nil {
		logger.Fatal("Cannot set up client", err)
	}
	c := Client{
		"My Fist Client",
		"http://localhost/client/clientID",
		prv,
		pub,
		common.AttachedJWS,
		"http://localhost:9090/tx",
	}
	return c
}
