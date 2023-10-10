package parser

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	tls "proxy/tls-fork"
	u "proxy/utils"

	"github.com/rs/zerolog/log"
)

type Parser struct {

	// tls cipher suite data
	cipherID uint16

	// secret data
	tlsParams TLSParameters

	// raw data
	tdClient tls.TrafficData
	tdServer tls.TrafficData

	// file handling
	clientFilePath   string
	serverFilePath   string
	storagePath      string
	secretPath       string
	authtagPath      string
	caPath           string
	serverRecordPath string
	clientRecordPath string

	// parsing/compute results
	h0       []byte
	h2       []byte
	h3       []byte
	h7       []byte
	msIn     []byte
	satsIn   []byte
	catsIn   []byte
	tkSappIn []byte
	ivSappIn []byte
	tkCappIn []byte
	ivCappIn []byte
}

func NewParser() (*Parser, error) {
	parser := new(Parser)

	// config parameters
	parser.storagePath = "./local_storage/"
	parser.serverRecordPath = "ServerSentRecords.raw"
	parser.clientRecordPath = "ClientSentRecords.raw"
	parser.caPath = "../certs/certificates/ca.crt"
	parser.clientFilePath = parser.storagePath + parser.clientRecordPath
	parser.serverFilePath = parser.storagePath + parser.serverRecordPath
	parser.secretPath = "../client/local_storage/kdc_shared.json"
	parser.authtagPath = "../client/local_storage/recordtag_public_input.json"

	// configure tls 1.3 parameters
	parser.cipherID = tls.TLS_AES_128_GCM_SHA256

	// get server certificate file
	caCert, err := ioutil.ReadFile(parser.caPath)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.ReadFile(parser.CaPath)")
		return nil, err
	}
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Error().Err(err).Msg("x509.SystemCertPool()")
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// initialize client/server transcript traffic parsers
	parser.tdClient = tls.NewTrafficData(parser.clientFilePath, tls.VersionTLS13, parser.cipherID, caCertPool)
	parser.tdServer = tls.NewTrafficData(parser.serverFilePath, tls.VersionTLS13, parser.cipherID, caCertPool)

	return parser, nil
}

// reads in client secret parameters to decrypt handshake traffic
func (p *Parser) ReadTLSParams() error {
	hss, err := NewTLSParams(p.secretPath)
	if err != nil {
		log.Error().Err(err).Msg("NewSFParams(p.secretPath)")
		return err
	}
	p.tlsParams = hss
	return nil
}

// read transcript reads raw tls traffic
// sets all tls messages
func (p *Parser) ReadTranscript() error {

	// sets client rawInput data
	err := p.tdClient.ReadTransmissionBitstream()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.ReadTransmissionBitstream()")
		return err
	}

	// set server rawInput data
	err = p.tdServer.ReadTransmissionBitstream()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.ReadTransmissionBitstream()")
		return err
	}

	// set client hello
	err = p.tdClient.ParseClientHello()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.parseHello()")
		return err
	}

	// set server hello
	err = p.tdServer.ParseServerHello()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseHello()")
		return err
	}

	// derive encryption keys from SHTS
	p.tdServer.SetCipherParameters(p.tlsParams.shts)

	// continue parsing server encrypted extension
	// attention: the function verifies the server side certificate
	err = p.tdServer.ParseServerEncryptedExtension()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseServerEncryptedExtension()")
		return err
	}

	// parse server certificate
	err = p.tdServer.ParseServerCertificate(p.tdClient.GetClientHello())
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseServerCertificate(p.tdClient.clientHello)")
		return err
	}

	// parse server finished message
	err = p.tdServer.ParseFinishedMsg()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseFinishedMsg()")
		return err
	}

	// set transcript digests
	err = p.setTranscriptDigests()
	if err != nil {
		log.Error().Err(err).Msg("p.setTranscriptDigests()")
		return err
	}

	return nil
}

func (p *Parser) setTranscriptDigests() error {

	// h0
	p.h0 = p.getH0()

	// h2
	h2, err := p.getH2()
	if err != nil {
		log.Error().Err(err).Msg("p.GetH2()")
		return err
	}
	p.h2 = h2

	// h3
	h3, err := p.getH3()
	if err != nil {
		log.Error().Err(err).Msg("p.GetH3()")
		return err
	}
	p.h3 = h3

	// h7
	h7, err := p.getH7()
	if err != nil {
		log.Error().Err(err).Msg("p.GetH7()")
		return err
	}
	p.h7 = h7

	return nil
}

func (p *Parser) getH0() []byte {

	// compute transcript hash
	transcript := tls.NewHashCipherSuiteTLS13ByID(p.cipherID)
	return transcript.Sum(nil)
}

func (p *Parser) getH2() ([]byte, error) {

	// deserialize transcripts
	chTranscript, err := p.tdClient.GetClientHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.GetClientHelloMarshal()")
		return nil, err
	}
	shTranscript, err := p.tdServer.GetServerHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetServerHelloMarshal()")
		return nil, err
	}

	// compute transcript hash
	transcript := tls.NewHashCipherSuiteTLS13ByID(p.cipherID)
	transcript.Write(chTranscript)
	transcript.Write(shTranscript)
	return transcript.Sum(nil), nil
}

func (p *Parser) getH3() ([]byte, error) {

	// deserialize transcripts
	chTranscript, err := p.tdClient.GetClientHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.GetClientHelloMarshal()")
		return nil, err
	}
	shTranscript, err := p.tdServer.GetServerHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetServerHelloMarshal()")
		return nil, err
	}
	eeTranscript, err := p.tdServer.GetEncryptedExtensionsMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetEncryptedExtensionsMarshal()")
		return nil, err
	}
	cmTranscript, err := p.tdServer.GetCertMsgMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetCertMsgMarshal()")
		return nil, err
	}
	cvTranscript, err := p.tdServer.GetCertVerifyMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetCertVerifyMarshal()")
		return nil, err
	}
	sfTranscript, err := p.tdServer.GetFinishedMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetFinishedMarshal()")
		return nil, err
	}

	// compute transcript hash
	transcript := tls.NewHashCipherSuiteTLS13ByID(p.cipherID)
	transcript.Write(chTranscript)
	transcript.Write(shTranscript)
	transcript.Write(eeTranscript)
	transcript.Write(cmTranscript)
	transcript.Write(cvTranscript)
	transcript.Write(sfTranscript)

	return transcript.Sum(nil), nil
}

func (p *Parser) getH7() ([]byte, error) {
	// deserialize transcripts
	chTranscript, err := p.tdClient.GetClientHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.GetClientHelloMarshal()")
		return nil, err
	}
	shTranscript, err := p.tdServer.GetServerHelloMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetServerHelloMarshal()")
		return nil, err
	}
	eeTranscript, err := p.tdServer.GetEncryptedExtensionsMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetEncryptedExtensionsMarshal()")
		return nil, err
	}
	cmTranscript, err := p.tdServer.GetCertMsgMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetCertMsgMarshal()")
		return nil, err
	}
	cvTranscript, err := p.tdServer.GetCertVerifyMarshal()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.GetCertVerifyMarshal()")
		return nil, err
	}

	// compute transcript hash
	transcript := tls.NewHashCipherSuiteTLS13ByID(p.cipherID)
	transcript.Write(chTranscript)
	transcript.Write(shTranscript)
	transcript.Write(eeTranscript)
	transcript.Write(cmTranscript)
	transcript.Write(cvTranscript)

	return transcript.Sum(nil), nil
}

func (p *Parser) CreateKdcPublicInput() error {

	// compute missing parameters
	p.msIn = tls.VMSin(p.tlsParams.intermediateHashdHSipad)
	p.satsIn = tls.VXATSin(p.tlsParams.intermediateHashMSipad, p.h3, "s ap traffic")
	p.catsIn = tls.VXATSin(p.tlsParams.intermediateHashMSipad, p.h3, "c ap traffic")
	p.tkSappIn = tls.VTkXAPPin(p.tlsParams.intermediateHashSATSipad)
	p.ivSappIn = tls.VIVin(p.tlsParams.intermediateHashSATSipad)
	p.tkCappIn = tls.VTkXAPPin(p.tlsParams.intermediateHashCATSipad)
	p.ivCappIn = tls.VIVin(p.tlsParams.intermediateHashCATSipad)

	return nil
}

func (p *Parser) StoreConfirmedKdcParameters() error {

	// json structure
	jsonData := make(map[string]string)
	// jsonData["H0"] = hex.EncodeToString(p.h0)
	// jsonData["H2"] = hex.EncodeToString(p.h2)
	// jsonData["H3"] = hex.EncodeToString(p.h3)
	// jsonData["H7"] = hex.EncodeToString(p.h7)
	// jsonData["SHTSin"] = hex.EncodeToString(p.tlsParams.shtsIn)
	jsonData["intermediateHashHSopad"] = hex.EncodeToString(p.tlsParams.intermediateHashHSopad)
	jsonData["MSin"] = hex.EncodeToString(p.msIn)
	jsonData["SATSin"] = hex.EncodeToString(p.satsIn)
	jsonData["tkSappIn"] = hex.EncodeToString(p.tkSappIn)
	// jsonData["ivSappIn"] = hex.EncodeToString(p.ivSappIn)
	jsonData["CATSin"] = hex.EncodeToString(p.catsIn)
	jsonData["tkCappIn"] = hex.EncodeToString(p.tkCappIn)
	// jsonData["ivCappIn"] = hex.EncodeToString(p.ivCappIn)

	// store data
	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = ioutil.WriteFile("./local_storage/kdc_confirmed.json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.WriteFile")
	}

	return nil
}

func (p *Parser) VerifyServerFinished() error {

	// verify SHTS to public input of zk kdc circuit
	ok2 := tls.VVerifySHTS(
		p.tlsParams.intermediateHashHSopad,
		p.tlsParams.shtsIn,
		p.tlsParams.shts,
	)
	if !ok2 {
		log.Error().Msg("tls.VVerifySHTS")
	}

	// derive SF from SHTS and check against plaintextSF
	// plaintextSFBytes, _ := hex.DecodeString(p.tdServer.GetFinishedRaw())
	ok1 := tls.VDeriveSF(p.tlsParams.shts, p.h7, p.tdServer.GetFinishedRaw())
	if !ok1 {
		log.Error().Msg("tls.VDeriveSF")
	}

	// make sure both verifications work
	if ok1 && ok2 {
		return nil
	} else {
		return errors.New("SF against public input verification failed")
	}

}

func (p *Parser) ReadRecordParams() (map[string]map[string]string, error) {

	// parse remaining chunks
	rps, err := p.tdServer.ParseRecordData()
	if err != nil {
		return nil, err
	}
	return rps, nil
}

func (p *Parser) CheckAuthTags(rps map[string]map[string]string) error {

	// read public input for record tag computation
	authPI, err := ReadRecordTagPI(p.authtagPath)
	if err != nil {
		return err
	}

	// init confirmed data
	confirmedJson := make(map[string]map[string]string)

	// loop over all sequence numbers and verify authentication tags
	for seq, record := range rps {

		r, ok := authPI[seq]
		if ok {
			ecb0 := r["ECB0"]
			ecbk := r["ECBK"]

			c := record["ciphertext"]
			ad := record["additionalData"]
			cipherChunks := c[:len(c)-(16*2)] // last 16 bytes

			// compute authtag
			tag := AuthTag13(ecb0, cipherChunks, ecbk, ad)

			// verify authtag
			if tag != c {
				return errors.New("authtag13 verification failed")
			}

			// create data structure of confirmed parameters
			// which are to be stored as confirmed
			jsonData := make(map[string]string)
			jsonData["tag"] = c[len(c)-(16*2):]
			jsonData["cipherChunks"] = cipherChunks
			jsonData["ecb0"] = ecb0
			jsonData["ecbk"] = ecbk
			confirmedJson[seq] = jsonData
		}
	}

	err = u.StoreMM(confirmedJson, "record_confirmed")
	if err != nil {
		return err
	}

	return nil
}
