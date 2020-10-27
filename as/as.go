package as

import (
	"../common"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rapidloop/skv"
	"go.uber.org/zap"
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
		logger.Error("Failed to open key-value store: ", err)
		os.Exit(1)
	}
	defer kvstore.Close()

	var jsonPub string
	err = kvstore.Get("pub", &jsonPub)
	if err != nil {
		logger.Error("Could not read from cache: ", err)
		os.Exit(1)
	}
	pub, err := jwk.ParseKey([]byte(jsonPub))
	if err != nil {
		logger.Error("Could not parse pub: ", err)
	}
	clientInfo.pubKey = pub
	return
}

func handleTx(w http.ResponseWriter, r *http.Request) {
	logger.Infof("Received %s", r.Header.Get("content-type"))
}
