package verifier

import (
	"encoding/hex"
	"strconv"
	"strings"

	glg "proxy/gnark_lib/circuits/gadgets"
	u "proxy/utils"

	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

func ComputeWitness() (witness.Witness, error) {

	// read in data
	params, err := readOracleParams()
	if err != nil {
		log.Error().Msg("readOracleParams()")
		return nil, err
	}

	// further preprocessing
	zeros := "00000000000000000000000000000000"
	ivCounter := addCounter(params["ivSapp"])
	chunkIndex, _ := strconv.Atoi(params["chunk_index"])
	substringStart, _ := strconv.Atoi(params["substring_start"])
	substringEnd, _ := strconv.Atoi(params["substring_end"])
	valueStart, _ := strconv.Atoi(params["value_start"])
	valueEnd, _ := strconv.Atoi(params["value_end"])
	// !!! policy value !!!
	threshold := 38001

	// kdc to bytes
	byteSlice, _ := hex.DecodeString(params["intermediateHashHSopad"])
	intermediateHashHSopadByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["MSin"])
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["SATSin"])
	SATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["tkSappIn"])
	tkSAPPinByteLen := len(byteSlice)
	// authtag to bytes
	byteSlice, _ = hex.DecodeString(ivCounter)
	ivCounterByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["ecb0"])
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["ecbk"])
	ecbkByteLen := len(byteSlice)
	// record to bytes
	byteSlice, _ = hex.DecodeString(params["ivSapp"])
	ivByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["cipher_chunks"])
	chipherChunksByteLen := len(byteSlice)
	substringByteLen := len(params["substring"])

	// witness definition kdc
	intermediateHashHSopadAssign := u.StrToIntSlice(params["intermediateHashHSopad"], true)
	MSinAssign := u.StrToIntSlice(params["MSin"], true)
	SATSinAssign := u.StrToIntSlice(params["SATSin"], true)
	tkSAPPinAssign := u.StrToIntSlice(params["tkSappIn"], true)
	// witness definition authtag
	ivCounterAssign := u.StrToIntSlice(ivCounter, true)
	zerosAssign := u.StrToIntSlice(zeros, true)
	ecb0Assign := u.StrToIntSlice(params["ecb0"], true)
	ecbkAssign := u.StrToIntSlice(params["ecbk"], true)
	// witness definition record
	ivAssign := u.StrToIntSlice(params["ivSapp"], true)
	chipherChunksAssign := u.StrToIntSlice(params["cipher_chunks"], true)
	substringAssign := u.StrToIntSlice(params["substring"], false)

	// witness values preparation
	assignment := glg.Tls13OracleWrapper{
		// kdc params
		DHSin:                  [64]frontend.Variable{},
		IntermediateHashHSopad: [32]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		SATSin:                 [32]frontend.Variable{},
		TkSAPPin:               [32]frontend.Variable{},
		// authtag params
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
		// record pararms
		PlainChunks:    make([]frontend.Variable, chipherChunksByteLen),
		Iv:             [12]frontend.Variable{},
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		ChunkIndex:     chunkIndex,
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
		Threshold:      threshold,
	}

	// kdc assign
	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < MSinByteLen; i++ {
		assignment.MSin[i] = MSinAssign[i]
	}
	for i := 0; i < SATSinByteLen; i++ {
		assignment.SATSin[i] = SATSinAssign[i]
	}
	for i := 0; i < tkSAPPinByteLen; i++ {
		assignment.TkSAPPin[i] = tkSAPPinAssign[i]
	}
	// authtag assign
	for i := 0; i < ivCounterByteLen; i++ {
		assignment.IvCounter[i] = ivCounterAssign[i]
	}
	for i := 0; i < zerosByteLen; i++ {
		assignment.Zeros[i] = zerosAssign[i]
	}
	for i := 0; i < ecbkByteLen; i++ {
		assignment.ECBK[i] = ecbkAssign[i]
	}
	for i := 0; i < ecb0ByteLen; i++ {
		assignment.ECB0[i] = ecb0Assign[i]
	}
	// record assign
	for i := 0; i < ivByteLen; i++ {
		assignment.Iv[i] = ivAssign[i]
	}
	for i := 0; i < chipherChunksByteLen; i++ {
		assignment.CipherChunks[i] = chipherChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}

	// fmt.Println("len intermediateHashHSopadByteLen:", intermediateHashHSopadByteLen)
	// fmt.Println("len MSin:", MSinByteLen)
	// fmt.Println("len SATSin:", SATSinByteLen)
	// fmt.Println("len tkSAPPin:", tkSAPPinByteLen)
	// fmt.Println("len ecbkByteLen:", ecbkByteLen)
	// fmt.Println("len ecb0ByteLen:", ecb0ByteLen)
	// fmt.Println("len chipherChunksByteLen:", chipherChunksByteLen)
	// fmt.Println("len ivByteLen:", ivByteLen)

	// fmt.Println("intermediateHashHSopadAssign:", intermediateHashHSopadAssign)
	// fmt.Println("MSinAssign:", MSinAssign)
	// fmt.Println("SATSinAssign:", SATSinAssign)
	// fmt.Println("tkSAPPinAssign:", tkSAPPinAssign)
	// fmt.Println("ivCounterAssign:", ivCounterAssign)
	// fmt.Println("ecbkAssign:", ecbkAssign)
	// fmt.Println("ecb0Assign:", ecb0Assign)
	// fmt.Println("chipherChunksAssign:", chipherChunksAssign)
	// fmt.Println("ivAssign:", ivAssign)

	// get witness
	witnessPublic, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Error().Err(err).Msg("frontend.NewWitness")
		return nil, err
	}

	// // // Binary [de]serialization
	// // data, _ := witnessPublic.MarshalBinary()
	// data, _ := os.ReadFile("../client/local_storage/circuits/oracle.pubwit")

	// reconstructed, _ := witness.New(ecc.BN254.ScalarField())
	// reconstructed.UnmarshalBinary(data)

	// // For pretty printing, we can do JSON conversions; they are not efficient and don't handle
	// // complex circuit structures well.

	// // first get the circuit expected schema
	// schema, err := frontend.NewSchema(&assignment)
	// if err != nil {
	// 	log.Error().Err(err).Msg("frontend.NewSchema")
	// 	return reconstructed, err
	// }
	// json, err := reconstructed.ToJSON(schema)
	// if err != nil {
	// 	log.Error().Err(err).Msg("reconstructed.ToJSON")
	// 	return reconstructed, err
	// }

	// fmt.Println(string(json))

	return witnessPublic, nil
}

func readOracleParams() (map[string]string, error) {

	// to be returned
	finalMap := make(map[string]string)

	// read in kdc publ params from client
	kdc_client_pub, err := u.ReadM("../client/local_storage/kdc_public_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range kdc_client_pub {
		finalMap[k] = v
	}

	// read in kdc pub params
	kdc_confirmed, err := u.ReadM("./local_storage/kdc_confirmed.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range kdc_confirmed {
		finalMap[k] = v
	}

	// read in authtag params
	tag_pub, err := u.ReadMM("./local_storage/record_confirmed.json")
	if err != nil {
		log.Error().Msg("u.ReadMM")
		return nil, err
	}

	// copy
	for k, v := range tag_pub {
		finalMap[k] = v
	}

	// read in record publ params
	record_pub, err := u.ReadM("../client/local_storage/recorddata_public_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range record_pub {
		finalMap[k] = v
	}

	return finalMap, nil
}

func addCounter(iv string) string {
	// add counter to iv bytes
	var sb strings.Builder
	for i := 0; i < len(iv); i++ {
		sb.WriteString(string(iv[i]))
	}
	for i := 0; i < 7; i++ {
		sb.WriteString("0")
	}
	sb.WriteString("1")
	// fmt.Println("len iv:", sb.String(), len(iv)/2)
	return sb.String()
}

func VerifyCircuit(backend string, publicWitness witness.Witness) error {

	switch backend {
	case "groth16":

		// read R1CS, proving key and verifying keys
		proof := groth16.NewProof(ecc.BN254)
		vk := groth16.NewVerifyingKey(ecc.BN254)
		u.Deserialize(proof, "../client/local_storage/circuits/oracle_"+backend+".proof")
		u.Deserialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

		err := groth16.Verify(proof, vk, publicWitness)
		return err

	case "plonk":

		// read constraint system, proving key and verifying keys
		proof := plonk.NewProof(ecc.BN254)
		vk := plonk.NewVerifyingKey(ecc.BN254)

		u.Deserialize(proof, "../client/local_storage/circuits/oracle_"+backend+".proof")
		u.Deserialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

		err := plonk.Verify(proof, vk, publicWitness)
		return err

	case "plonkFRI":

	}

	return nil
}
