package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
    "path/filepath"

	"github.com/rs/zerolog/log"
)

type CombinedData struct {
    KDCShared         map[string]interface{} `json:"kdc_shared"`
    RecordTagPublic   map[string]interface{} `json:"recordtag_public"`
    RecordDataPublic  map[string]interface{} `json:"recorddata_public"`
    KDCPublicInput    map[string]interface{} `json:"kdc_public_input"`
}

func ReadM(filePath string) (map[string]string, error) {

	// open file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return nil, err
	}
	defer file.Close()

	// read in data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("io.ReadAll(file)")
		return nil, err
	}

	// parse json
	var objmap map[string]string
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return nil, err
	}

	return objmap, nil
}

func ReadMM(filePath string) (map[string]string, error) {

	// open file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return nil, err
	}
	defer file.Close()

	// read in data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("io.ReadAll(file)")
		return nil, err
	}

	// parse json
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return nil, err
	}

	// catch server record data
	innerMapFinal := make(map[string]string)
	for _, v := range objmap {

		// inner map parsing
		innerMap := make(map[string]string)
		err = json.Unmarshal(v, &innerMap)
		if err != nil {
			log.Error().Err(err).Msg("json.Unmarshal(v, &innerMap)")
			return nil, err
		}

		// copy
		for k2, v2 := range innerMap {
			innerMapFinal[k2] = v2
		}
	}

	return innerMapFinal, nil
}

func StoreM(jsonData map[string]string, filename string) error {

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = os.WriteFile("./local_storage/"+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

func StoreMM(mapmap map[string]map[string]string, filename string) error {

	file, err := json.MarshalIndent(mapmap, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}

	err = os.WriteFile("./local_storage/"+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

// serialize gnark object to given file
func Serialize(gnarkObject io.WriterTo, fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		log.Error().Err(err).Msg("os.Create(fileName)")
	}

	_, err = gnarkObject.WriteTo(f)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.WriteTo(f)")
	}
}

// deserialize gnark object from given file
func Deserialize(gnarkObject io.ReaderFrom, fileName string) {
	f, err := os.Open(fileName)
	if err != nil {
		log.Error().Err(err).Msg("os.Open(fileName)")
	}

	_, err = gnarkObject.ReadFrom(f)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.ReadFrom(f)")
	}
}

// debug function to check if serialization and deserialization work
func CheckSum(gnarkObject io.WriterTo, objName string) []byte {

	// compute hash of bytes
	buf := new(bytes.Buffer)
	_, err := gnarkObject.WriteTo(buf)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.WriteTo(buf)")
	}

	hash := md5.Sum(buf.Bytes())
	log.Debug().Str("md5", hex.EncodeToString(hash[:])).Msg("checkSum of " + objName)

	return buf.Bytes()
}

func StrToIntSlice(inputData string, hexRepresentation bool) []int {

	// check if inputData in hex representation
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, err := hex.DecodeString(inputData)
		if err != nil {
			log.Error().Msg("hex.DecodeString error.")
		}
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	// convert byte slice to int numbers which can be passed to gnark frontend.Variable
	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}

	return data
}

func TrascriptStats() error {

	filename1 := "ClientSentRecords.raw"
	f1, err := getFileInfo("./local_storage/" + filename1)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename1+" is %d bytes long.\n", f1.Size())

	filename2 := "ServerSentRecords.raw"
	f2, err := getFileInfo("./local_storage/" + filename2)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename2+" is %d bytes long.\n", f2.Size())

	filename3 := "oracle_groth16.ccs"
	f3, err := getFileInfo("./local_storage/circuits/" + filename3)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename3+" is %d bytes long.\n", f3.Size())

	filename4 := "oracle_groth16.pk"
	f4, err := getFileInfo("./local_storage/circuits/" + filename4)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename4+" is %d bytes long.\n", f4.Size())

	filename5 := "oracle_groth16.vk"
	f5, err := getFileInfo("./local_storage/circuits/" + filename5)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename5+" is %d bytes long.\n", f5.Size())

	return nil
}

func getFileInfo(filePath string) (os.FileInfo, error) {
	f1, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f1.Close()

	fi, err := f1.Stat()
	if err != nil {
		return nil, err
	}
	return fi, nil
}

func SaveJSONToFile(filename string, data map[string]interface{}) error {
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return err
    }
    
    fullPath := filepath.Join("local_storage", filename)
    
    err = os.WriteFile(fullPath, jsonData, 0644)
    if err != nil {
        return err
    }
    return nil
}