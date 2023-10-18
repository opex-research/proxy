package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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

	// Session ID for measurements
	sessionID := flag.String("sessionid", "", "session ID for the client.")

	// Set Proxy URL's
	proxyListenerURL := flag.String("proxylistener", "", "URL of the proxy server")
	proxyServerURL := flag.String("proxyserver", "", "URL of the proxy server")

	// parse all flags
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// activated check
	log.Debug().Msg("Debugging activated.")

	// Measurement initialization
	measurements := u.NewMeasurements(*sessionID)

	// start proxy in listener mode
	if *listen {
		// Start the listener in a separate Goroutine
		go func() {
			listener := l.NewListener(*proxyListenerURL)
			err := listener.Listen()
			if err != nil {
				log.Error().Err(err).Msg("listener.Listen()")
			}
		}()

		// Give it a moment to initialize (optional but can be helpful)
		time.Sleep(1 * time.Second)

		// Start the HTTP server
		startServer(*proxyServerURL, measurements)
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
func startServer(proxyServerURL string, measurements *u.Measurements) {
	measurements.Start("postprocessAndSetupHandler")
	http.HandleFunc("/postprocess", postprocessAndSetupHandler(measurements))
	measurements.End("postprocessAndSetupHandler")
	measurements.Start("verifyHandler")
	http.HandleFunc("/verify", verifyHandler(measurements))
	measurements.End("verifyHandler")

	log.Info().Msg("HTTP Server started at " + proxyServerURL)
	err := http.ListenAndServe(proxyServerURL, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start the HTTP server")
	}
}

func postprocessAndSetupHandler(measurements *u.Measurements) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msg("Starting postprocessAndSetupHandler()!")

		// Get the function from postprocessHandler
		postprocessFunc := postprocessHandler(measurements)
		body, err := postprocessFunc(r) // Here, invoke the function with the request
		if err != nil {
			respondWithError(w, "Postprocess Error", err)
			return
		}

		if body != nil {
			w.WriteHeader(http.StatusOK)
			w.Write(body)
			return
		}

		// Assuming that setupHandler is similar to postprocessHandler and returns a function
		setupFunc := setupHandler(measurements)
		body, err = setupFunc(r) // Again, invoke the function with the request
		if err != nil {
			respondWithError(w, "Setup Error", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}
}

// handle postprocess
// verifies SF with public data
// verifies server certificate
func postprocessHandler(measurements *u.Measurements) func(*http.Request) ([]byte, error) {
	return func(r *http.Request) ([]byte, error) {
		measurements.Start("PostProcessComplete")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading request body")
		}

		defer r.Body.Close()

		var combinedData u.CombinedData
		err = json.Unmarshal(body, &combinedData)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling combined JSON data")
		}

		// Save each component to a file in /local_storage
		err = u.SaveJSONToFile("kdc_shared.json", combinedData.KDCShared)
		if err != nil {
			return nil, fmt.Errorf("Failed to save kdc_shared.json")
		}

		err = u.SaveJSONToFile("recordtag_public_input.json", combinedData.RecordTagPublic)
		if err != nil {
			return nil, fmt.Errorf("Failed to save recordtag_public_input.json")
		}

		err = u.SaveJSONToFile("recorddata_public_input.json", combinedData.RecordDataPublic)
		if err != nil {
			return nil, fmt.Errorf("Failed to save recorddata_public_input.json")
		}

		err = u.SaveJSONToFile("kdc_public_input.json", combinedData.KDCPublicInput)
		if err != nil {
			return nil, fmt.Errorf("Failed to save kdc_public_input.json")
		}

		log.Debug().Msg("All files sent by client stored successfully!")

		// Get Sequence Number from the data provided by the client
		seqInterface, ok := combinedData.RecordDataPublic["sequence_number"]
		if !ok {
			return nil, fmt.Errorf("sequence_number not found in RecordDataPublic")
		}
		seq, ok := seqInterface.(string)
		if !ok {
			return nil, fmt.Errorf("sequence_number is not a string")
		}

		// initialize parser
		parser, err := p.NewParser()
		if err != nil {
			return nil, fmt.Errorf("tls.NewParser()")
		}

		// read in secrets which have been shared by prover
		err = parser.ReadTLSParams()
		if err != nil {
			return nil, fmt.Errorf("parser.ReadTLSParams()")
		}

		// read transcript of interest to create kdc parameters
		// parser.ReadTranscript verifies the server certificate
		err = parser.ReadTranscript()
		if err != nil {
			return nil, fmt.Errorf("parser.ReadTranscript()")
		}

		// verify SF and SHTS derivation against public input values (intermediate hashes)
		err = parser.VerifyServerFinished()
		if err != nil {
			return nil, fmt.Errorf("parser.VerifySF()")
		}

		// compute public input parameters
		err = parser.CreateKdcPublicInput()
		if err != nil {
			return nil, fmt.Errorf("parser.CreateKdcPublicInput()")
		}

		// store confirmed kdc parameters
		err = parser.StoreConfirmedKdcParameters()
		if err != nil {
			return nil, fmt.Errorf("parser.StoreConfirmedKdcParameters()")
		}

		// read record parameters (ciphertext chunks + tag)
		rps, err := parser.ReadRecordParams()
		if err != nil {
			return nil, fmt.Errorf("parser.ReadRecordParams()")
		}
		log.Debug().Interface("recordParams", rps).Msg("Record Parameters.")

		// verify authtag and confirm public output for tag verification
		// further stores confirmed parameters
		err = parser.CheckAuthTags(seq, rps)
		if err != nil {
			return nil, fmt.Errorf("parser.CheckAuthTag()")
		}

		measurements.End("PostProcessComplete")

		// If you want to proceed to setupHandler without sending any message, return nil
		return nil, nil
	}
}

func setupHandler(measurements *u.Measurements) func(*http.Request) ([]byte, error) {
	return func(r *http.Request) ([]byte, error) {

		measurements.Start("SetupComplete")

		circuit, err := v.GetCircuit()
		if err != nil {
			return nil, err
		}

		backend := "groth16"
		measurements.Start("CompileCircuit")
		ccs, err := v.CompileCircuit(backend, circuit)
		measurements.End("CompileCircuit")
		if err != nil {
			return nil, err
		}

		measurements.Start("ComputeSetup")
		err = v.ComputeSetup(backend, ccs)
		measurements.End("ComputeSetup")
		if err != nil {
			return nil, err
		}

		pkpath := "local_storage/circuits/oracle_" + backend + ".pk"
		_pk, _ := os.ReadFile(pkpath)

		measurements.End("SetupComplete")

		return _pk, nil
	}
}

func verifyHandler(measurements *u.Measurements) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		backend := "groth16"

		// Read the proof data from the request body
		proofData, err := io.ReadAll(r.Body)
		if err != nil {
			respondWithError(w, "Failed to read proof data from request", err)
			return
		}

		// NEW: Log the size of received proof data and its first few bytes
		log.Debug().Int("bytesReceived", len(proofData)).Msg("Total size of proof received from client.")

		// Write the proof data to the desired file
		proofFilePath := "local_storage/circuits/oracle_" + backend + ".proof"
		err = os.WriteFile(proofFilePath, proofData, 0644)
		if err != nil {
			respondWithError(w, "Failed to write proof data to file", err)
			return
		}

		measurements.Start("ComputeWitness")
		// circuit should be parsed because it's compiled by a trusted third-party.
		assignment, err := v.ComputeWitness()
		if err != nil {
			respondWithError(w, "v.ComputeWitness()", err)
			return
		}
		measurements.End("ComputeWitness")

		measurements.Start("VerifyCircuit")
		err = v.VerifyCircuit(backend, assignment)
		if err != nil {
			respondWithError(w, "v.VerifyCircuit()", err)
			return
		}
		measurements.End("VerifyCircuit")

		// Check and create /performance directory if it doesn't exist
		if err = u.CheckAndCreateDir("performance"); err != nil {
			log.Error().Err(err).Msg("Failed to create performance directory.")
			return
		}

		// Dump the measurements to a CSV file in /performance directory
		err = measurements.DumpToCSV("performance/measurements_proxy.csv")
		if err != nil {
			log.Error().Err(err).Msg("Failed to write measurements to CSV.")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Verification completed"))
	}
}

func respondWithError(w http.ResponseWriter, logMsg string, err error) {
	log.Error().Err(err).Msg(logMsg)
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"status": "error", "message": "` + logMsg + `: ` + err.Error() + `"}`))
}
