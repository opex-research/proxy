package verifier

import (
	"encoding/hex"
	glg "proxy/gnark_lib/circuits/gadgets"
	u "proxy/utils"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"

	// "github.com/consensys/gnark/backend/plonkfri"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func GetCircuit() (frontend.Circuit, error) {

	// read data which defines circuit size
	params, err := readCircuitParams()
	if err != nil {
		log.Error().Err(err).Msg("readCircuitParams()")
		return nil, err
	}

	// cipher chunks bytes
	cipherChunksBytes, _ := hex.DecodeString(params["cipher_chunks"])
	cipherChunksByteLen := len(cipherChunksBytes)
	// convert str to int
	sss, _ := strconv.Atoi(params["substring_start"])
	sse, _ := strconv.Atoi(params["substring_end"])
	vs, _ := strconv.Atoi(params["value_start"])
	ve, _ := strconv.Atoi(params["value_end"])

	// var circuit kdcServerKey
	circuit := glg.Tls13OracleWrapper{
		PlainChunks:    make([]frontend.Variable, cipherChunksByteLen),
		CipherChunks:   make([]frontend.Variable, cipherChunksByteLen),
		Substring:      make([]frontend.Variable, len(params["substring"])),
		SubstringStart: sss,
		SubstringEnd:   sse,
		ValueStart:     vs,
		ValueEnd:       ve,
	}

	return &circuit, nil
}

func readCircuitParams() (map[string]string, error) {

	// to be returned
	finalMap := make(map[string]string)

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

func CompileCircuit(backend string, circuit frontend.Circuit) (constraint.ConstraintSystem, error) {

	// init builders
	var builder frontend.NewBuilder
	// var srs kzg.SRS
	switch backend {
	case "groth16":
		builder = r1cs.NewBuilder
	case "plonk":
		builder = scs.NewBuilder
	case "plonkFRI":
		builder = scs.NewBuilder
	}

	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
	if err != nil {
		log.Error().Msg("frontend.Compile")
		return nil, err
	}

	// serialize constraint system
	u.Serialize(ccs, "./local_storage/circuits/oracle_"+backend+".ccs")
	// checkSum(ccs, "CCS")

	return ccs, nil
}

func ComputeSetup(backend string, ccs constraint.ConstraintSystem) error {

	// kzg setup if using plonk
	var srs kzg.SRS
	if backend == "plonk" {
		srs, err := test.NewKZGSRS(ccs)
		if err != nil {
			log.Error().Msg("test.NewKZGSRS(ccs)")
			return err
		}
		u.Serialize(srs, "./local_storage/circuits/oracle_"+backend+".srs")
	}

	// proof system execution
	switch backend {
	case "groth16":

		// setup
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			log.Error().Msg("groth16.Setup")
			return err
		}
		u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

	case "plonk":

		// setup
		pk, vk, err := plonk.Setup(ccs, srs)
		if err != nil {
			log.Error().Msg("plonk.Setup")
			return err
		}
		u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

	case "plonkFRI":

		// setup
		// pk, vk, err := plonkfri.Setup(ccs)
		// if err != nil {
		// 	log.Error().Msg("plonkfri.Setup")
		// 	return err
		// }
		// u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		// u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")
	}
	return nil
}
