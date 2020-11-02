package common

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/rapidloop/skv"
	"go.uber.org/multierr"
)

const CachePath = "/misc/gnap/core/my_cache.bolt"

// Message security
const (
	DetachedSignature = iota
	AttachedJWS
)

type Client struct {
	Name, URI string
	Prv, Pub  jwk.Key
	// Message security (aka token binding) preference
	MessageSecurity int
	ASURI           string
}

type AuthzServer struct {
	Name, URI string
	Prv, Pub  jwk.Key
}

func GenerateKeypair() (prv, pub jwk.Key, err error) {
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
		return nil, nil, errors.Wrapf(err, "Failed to assign key ID to Prv")
	}
	err = jwk.AssignKeyID(pub)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to assign key ID to Pub")
	}
	err = pub.Set("alg", "RS256") // TODO: hardcoded
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to set alg on Pub")
	}
	return
}

func LoadClient(kvstore *skv.KVStore, prefix string, withPrivate bool) (Client, error) {
	var client Client
	var jsonPub string
	err := kvstore.Get(prefix+"Name", &client.Name)
	multierr.AppendInto(&err, kvstore.Get(prefix+"URI", &client.URI))
	multierr.AppendInto(&err, kvstore.Get(prefix+"asUri", &client.ASURI))
	multierr.AppendInto(&err, kvstore.Get(prefix+"MessageSecurity", &client.MessageSecurity))
	multierr.AppendInto(&err, kvstore.Get(prefix+"Pub", &jsonPub))
	if err != nil {
		return client, errors.Wrapf(err, "Failed to read client properties")
	}
	var jsonPrv string
	if withPrivate {
		err := kvstore.Get(prefix+"Prv", &jsonPrv)
		if err != nil {
			return client, errors.Wrapf(err, "Failed to read client private key")
		}
		prv, err := jwk.ParseKey([]byte(jsonPrv))
		if err != nil {
			return client, errors.Wrapf(err, "Could not parse Prv")
		}
		client.Prv = prv
	}
	pub, err := jwk.ParseKey([]byte(jsonPub))
	if err != nil {
		return client, errors.Wrapf(err, "Could not parse Pub")
	}
	client.Pub = pub
	return client, nil
}
