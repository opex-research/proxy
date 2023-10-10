package parser

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/rs/zerolog/log"
)

type TLSParameters struct {
	shts                     []byte
	shtsIn                   []byte
	intermediateHashHSopad   []byte
	intermediateHashdHSipad  []byte
	intermediateHashCATSipad []byte
	intermediateHashMSipad   []byte
	intermediateHashSATSipad []byte
	hashKeyCapp              []byte
	hashIvCapp               []byte
	hashKeySapp              []byte
	hashIvSapp               []byte
}

func NewTLSParams(filePath string) (TLSParameters, error) {

	// init new struct
	hss := TLSParameters{}

	// open file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return hss, err
	}
	defer file.Close()

	// read in data
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.ReadAll(file)")
		return hss, err
	}

	// parse json
	var objmap map[string]string
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return hss, err
	}

	// convert values to byte slices
	hss.shts, _ = hex.DecodeString(objmap["SHTS"])
	hss.shtsIn, _ = hex.DecodeString(objmap["SHTSin"])
	hss.intermediateHashHSopad, _ = hex.DecodeString(objmap["intermediateHashHSopad"])
	hss.intermediateHashCATSipad, _ = hex.DecodeString(objmap["intermediateHashCATSipad"])
	hss.intermediateHashMSipad, _ = hex.DecodeString(objmap["intermediateHashMSipad"])
	hss.intermediateHashSATSipad, _ = hex.DecodeString(objmap["intermediateHashSATSipad"])
	hss.intermediateHashdHSipad, _ = hex.DecodeString(objmap["intermediateHashdHSipad"])
	hss.hashKeyCapp, _ = hex.DecodeString(objmap["hashKeyCapp"])
	hss.hashIvCapp, _ = hex.DecodeString(objmap["hashIvCapp"])
	hss.hashKeySapp, _ = hex.DecodeString(objmap["hashKeySapp"])
	hss.hashIvSapp, _ = hex.DecodeString(objmap["hashIvSapp"])

	// take out values of interest
	return hss, nil
}
