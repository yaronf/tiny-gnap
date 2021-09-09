module github.com/yaronf/tiny-gnap

go 1.14

replace github.com/yaronf/tiny-gnap/common => /Users/ysheffer/misc/gnap/core/common

require (
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/lestrrat-go/jwx v1.0.6-0.20201029222056-556b0e99b983
	github.com/pkg/errors v0.9.1
	github.com/rapidloop/skv v0.0.0-20180909015525-9def2caac4cc
	go.uber.org/multierr v1.7.0
	go.uber.org/tools v0.0.0-20190618225709-2cfd321de3ee // indirect
	go.uber.org/zap v1.19.1
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de // indirect
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
)
