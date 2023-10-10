package main

import (
	"flag"
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

	// postprocess
	postprocess := flag.Bool("postprocess", false, "parse captured transcript to verify key derivation and create public input.")

	// check for -setup flag
	setup := flag.Bool("setup", false, "compiles zk circuit and computes+stores the setup parameters.")

	// verify
	verify := flag.Bool("verify", false, "verify zk data proof.")

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
		listener := l.NewListener()
		err := listener.Listen()
		if err != nil {
			log.Error().Err(err).Msg("listener.Listen()")
			return
		}
	}

	// handle postprocess
	// verifies SF with public data
	// verifies server certificate
	if *postprocess {

		start := time.Now()

		// initialize parser
		parser, err := p.NewParser()
		if err != nil {
			log.Error().Msg("tls.NewParser()")
			return
		}

		// read in secrets which have been shared by prover
		err = parser.ReadTLSParams()
		if err != nil {
			log.Error().Msg("parser.ReadTLSParams()")
			return
		}

		// read transcript of interest to create kdc parameters
		// parser.ReadTranscript verifies the server certificate
		err = parser.ReadTranscript()
		if err != nil {
			log.Error().Msg("parser.ReadTranscript()")
			return
		}

		// verify SF and SHTS derivation against public input values (intermediate hashes)
		err = parser.VerifyServerFinished()
		if err != nil {
			log.Error().Msg("parser.VerifySF()")
			return
		}

		// compute public input parameters
		err = parser.CreateKdcPublicInput()
		if err != nil {
			log.Error().Msg("parser.CreateKdcPublicInput()")
			return
		}

		// store confirmed kdc parameters
		err = parser.StoreConfirmedKdcParameters()
		if err != nil {
			log.Error().Msg("parser.StoreConfirmedKdcParameters()")
			return
		}

		// read record parameters (ciphertext chunks + tag)
		rps, err := parser.ReadRecordParams()
		if err != nil {
			log.Error().Msg("parser.ReadRecordParams()")
			return
		}

		// verify authtag and confirm public output for tag verification
		// further stores confirmed parameters
		err = parser.CheckAuthTags(rps)
		if err != nil {
			log.Error().Msg("parser.CheckAuthTag()")
			return
		}

		elapsed := time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("proxy postprocess time.")

	}

	// call setup
	if *setup {

		circuit, err := v.GetCircuit()
		if err != nil {
			log.Error().Msg("v.GetCircuit()")
		}

		backend := "groth16"
		ccs, err := v.CompileCircuit(backend, circuit)
		if err != nil {
			log.Error().Msg("v.CompileCircuit()")
		}

		// computes the setup parameters
		err = v.ComputeSetup(backend, ccs)
		if err != nil {
			log.Error().Msg("v.ComputeSetup()")
		}
	}

	// handle zk verification
	if *verify {
		// circuit should be parsed. cause its compiled by trusted third-party.
		assignment, err := v.ComputeWitness()
		if err != nil {
			log.Error().Msg("v.CircuitAssign()")
			return
		}

		backend := "groth16"
		err = v.VerifyCircuit(backend, assignment)
		if err != nil {
			log.Error().Err(err).Msg("v.VerifyCircuit()")
			return
		}
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
