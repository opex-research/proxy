package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// checks logging flag if program is called as ./main.go -debug
func setLogger() {

	// logging settings
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	debug := flag.Bool("debug", false, "sets log level to debug")
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// activated check
	log.Debug().Msg("Debugging activated.")
}

func main() {

	// log
	setLogger()

	// configs
	HostAddr := "localhost"
	HostPort := "8082"
	StoragePath := "./local_storage/"
	ProverSentRecordsFileName := "ProverSentRecords"
	ServerSentRecordsFileName := "ServerSentRecords"

	// http handler to catch incoming requests
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Info().Msg("start PROXY capturing.")

		if r.Method != http.MethodConnect {
			http.Error(w, "Non-http-connect Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		fmt.Println("host:", r.Host)
		// tcp connection to destination server/host (e.g. paypal)
		conn, err := net.DialTimeout("tcp", r.Host, time.Second*5)
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to dial %s, error: %s", r.Host, err.Error()), http.StatusServiceUnavailable)
			return
		}
		defer conn.Close()

		// write status 200
		w.WriteHeader(http.StatusOK)

		// typecast responsewriter to http.Hijacker struct
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Proxy: Unable to typecast hijacker.", http.StatusInternalServerError)
			return
		}

		// hijack connection to client/prover
		reqConn, wbuf, err := hj.Hijack()
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to hijack connection %s", err), http.StatusInternalServerError)
			return
		}
		defer reqConn.Close()
		defer wbuf.Flush()

		// prepare capturing configurations
		proverPath := StoragePath + ProverSentRecordsFileName
		serverPath := StoragePath + ServerSentRecordsFileName

		// errorgroup to catch and wait for connections to finish
		g := new(errgroup.Group)

		// pipe incoming traffic from client to destination connection
		g.Go(func() error {
			return pipe(reqConn, conn, proverPath)
		})

		// pipe destination server responses to client connection
		g.Go(func() error {
			return pipe(conn, reqConn, serverPath)
		})

		// wait until goroutines finish and print any error
		if err := g.Wait(); err != nil {
			log.Error().Err(err).Msg("g.Wait()")
		}

		log.Debug().Msg("stop PROXY capturing.")
	})

	// start proxy server
	srvProxy := http.Server{Addr: HostAddr + ":" + HostPort, Handler: h}
	log.Info().Msg("PROXY on " + HostAddr + ":" + HostPort)

	// start service
	err := srvProxy.ListenAndServe()
	if err != nil {
		log.Error().Err(err).Msg("srvProxy.ListenAndServe()")
	}

}

func pipe(src net.Conn, dst net.Conn, path string) error {

	// open files to store captured traffic
	var err error
	fileHandleRaw, err := os.OpenFile(path+".raw", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	fileHandleTxt, err := os.OpenFile(path+".txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer fileHandleRaw.Close()
	defer fileHandleTxt.Close()

	// code taken from io.copy golang std lib
	// loop copies all data from connection source to connection destination
	for {
		// init buffer
		tmp := make([]byte, 4068)

		// read data from source connection into buffer slice
		m, err := src.Read(tmp)

		// measure time to copy 4kB
		start := time.Now()

		// handle read error
		if err != nil && err != io.EOF {
			if opErr, ok := err.(*net.OpError); ok {
				if strings.Contains(opErr.Error(), "use of closed network connection") {
					return nil
				}
			}
			log.Error().Err(err).Msg("tried reading closed network connection")
			return err

			// catch end of file delimiter and close connection
		} else if err == io.EOF {
			dst.Close()
			return nil
		}

		// from here on, handle data. no error and no end of file found
		// write captured data to files
		bufferWrite(tmp[:m], fileHandleRaw, fileHandleTxt)

		// copy data from slice buffer to the destination connection
		m, err = dst.Write(tmp[:m])
		if err != nil && err != io.EOF {
			log.Error().Err(err).Msg("dst.Write(tmp[:m])")
			return err
		}

		// measure proxy delay
		elapsed := time.Since(start)
		log.Debug().Str("time", elapsed.String()).Msg("proxy copy connection data took.")
	}

	return err
}

func bufferWrite(msg []byte, fileHandleRaw *os.File, fileHandleTxt *os.File) {

	// flush bytes to file
	buf := bufio.NewWriter(fileHandleRaw)
	buf.Write(msg)
	err := buf.Flush()
	if err != nil {
		log.Error().Err(err).Msg("buf.Flush()")
	}

	// flush hex string encoded bytes to file
	buf2 := bufio.NewWriter(fileHandleTxt)
	buf2.WriteString(hex.EncodeToString(msg))
	err = buf2.Flush()
	if err != nil {
		log.Error().Err(err).Msg("buf2.Flush()")
	}
}
