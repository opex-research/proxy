package main

import (
	"flag"
	"time"
	"net/http"

	// "crypto/tls"

	l "proxy/listen"
	p "proxy/parser"
	u "proxy/utils"
	v "proxy/verifier"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {

	// logging settings
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// checks logging flag if program is called as ./main.go -debug
	debug := flag.Bool("debug", false, "sets log level to debug.")

	// checks if proxy should be executed in monitoring mode
	listen := flag.Bool("listen", false, "listen for tls connections and stores communication transcripts.")

	// statistics on transcript data
	stats := flag.Bool("stats", false, "measures transcript sizes and sizes of local storage files.")

	// parse all flags
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// activated check
	log.Debug().Msg("Debugging activated.")

	// start proxy in listener mode
	if *listen {
    	// Start the listener in a separate Goroutine
		go func() {
			listener := l.NewListener()
			err := listener.Listen()
			if err != nil {
				log.Error().Err(err).Msg("listener.Listen()")
			}
		}()

		// Give it a moment to initialize (optional but can be helpful)
		time.Sleep(1 * time.Second)

		// Start the HTTP server
		startServer()
	}


	// additional stats
	if *stats {
		err := u.TrascriptStats()
		if err != nil {
			log.Error().Msg("u.TrascriptStats()")
			return
		}
	}

}

// startServer initializes the HTTP server and routes
func startServer() {
    http.HandleFunc("/postprocess", postprocessAndSetupHandler)
    http.HandleFunc("/verify", verifyHandler)

    log.Info().Msg("HTTP Server started at :8080")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to start the HTTP server")
    }
}

func postprocessAndSetupHandler(w http.ResponseWriter, r *http.Request) {

	postprocessHandler(w, r)

	if w.Header().Get("Content-Type") == "application/json" {
		return
	}

	setupHandler(w, r)
}


// handle postprocess
// verifies SF with public data
// verifies server certificate
func postprocessHandler(w http.ResponseWriter, r *http.Request) {
    start := time.Now()

    // initialize parser
    parser, err := p.NewParser()
    if err != nil {
        respondWithError(w, "tls.NewParser()", err)
        return
    }

    // read in secrets which have been shared by prover
    err = parser.ReadTLSParams()
    if err != nil {
        respondWithError(w, "parser.ReadTLSParams()", err)
        return
    }

    // read transcript of interest to create kdc parameters
    // parser.ReadTranscript verifies the server certificate
    err = parser.ReadTranscript()
    if err != nil {
        respondWithError(w, "parser.ReadTranscript()", err)
        return
    }

    // verify SF and SHTS derivation against public input values (intermediate hashes)
    err = parser.VerifyServerFinished()
    if err != nil {
        respondWithError(w, "parser.VerifySF()", err)
        return
    }

    // compute public input parameters
    err = parser.CreateKdcPublicInput()
    if err != nil {
        respondWithError(w, "parser.CreateKdcPublicInput()", err)
        return
    }

    // store confirmed kdc parameters
    err = parser.StoreConfirmedKdcParameters()
    if err != nil {
        respondWithError(w, "parser.StoreConfirmedKdcParameters()", err)
        return
    }

    // read record parameters (ciphertext chunks + tag)
    rps, err := parser.ReadRecordParams()
    if err != nil {
        respondWithError(w, "parser.ReadRecordParams()", err)
        return
    }

    // verify authtag and confirm public output for tag verification
    // further stores confirmed parameters
    err = parser.CheckAuthTags(rps)
    if err != nil {
        respondWithError(w, "parser.CheckAuthTag()", err)
        return
    }

    elapsed := time.Since(start)
    log.Debug().Str("elapsed", elapsed.String()).Msg("proxy postprocess time.")

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Postprocess completed"))
}

func setupHandler(w http.ResponseWriter, r *http.Request) {
    circuit, err := v.GetCircuit()
	if err != nil {
		respondWithError(w, "v.GetCircuit()", err)
		return
	}

	backend := "groth16"
	ccs, err := v.CompileCircuit(backend, circuit)
	if err != nil {
		respondWithError(w, "v.CompileCircuit()", err)
		return
	}

	err = v.ComputeSetup(backend, ccs)
	if err != nil {
		respondWithError(w, "v.ComputeSetup()", err)
		return
	}

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Setup completed"))
}


func verifyHandler(w http.ResponseWriter, r *http.Request) {
    // circuit should be parsed because it's compiled by a trusted third-party.
    assignment, err := v.ComputeWitness()
    if err != nil {
        respondWithError(w, "v.ComputeWitness()", err)
        return
    }

    backend := "groth16"
    err = v.VerifyCircuit(backend, assignment)
    if err != nil {
        respondWithError(w, "v.VerifyCircuit()", err)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Verification completed"))
}


func respondWithError(w http.ResponseWriter, logMsg string, err error) {
	log.Error().Err(err).Msg(logMsg)
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"status": "error", "message": "` + logMsg + `: ` + err.Error() + `"}`))
}