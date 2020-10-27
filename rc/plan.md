* Components: RC, AS, RS
* Push from Go test in RC
* Persistence (e.g. for credentials), [diskv](https://github.com/peterbourgon/diskv) or even [go-cache](https://github.com/patrickmn/go-cache)
* [State machine](https://github.com/looplab/fsm)
* Standard HTTP framework, no special REST framework
* [JOSE](https://github.com/square/go-jose) library
* Use interface{} for polymorphism, sigh
* Ended up using jwx for JOSE (great library!)
* And skv as a key-value store (not great, you immediately bump into "gob" issues)