package transpiler

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

type Transpiler struct {
	FileName   string
	Template   *template.Template
	Constraint string
}

func NewTranspiler(filename, constraint string) *Transpiler {
	generatorTempl := getTemplate1()
	t := template.Must(template.New("generator").Parse(generatorTempl))
	transpiler := &Transpiler{Template: t, FileName: filename, Constraint: constraint}
	return transpiler
}

func (t *Transpiler) Transpile() error {

	// template data
	var data map[string]string
	if t.Constraint == "GT" {
		data = getComparatorGT(t.FileName)
	} else if t.Constraint == "LT" {
		data = getComparatorLT(t.FileName)
	} else if t.Constraint == "EQ" {
		data = getComparatorEQ(t.FileName)
	} else {
		err := errors.New("Constraint not supported.")
		log.Println("transpile error: constraint not found")
		return err
	}

	// transpile constraints into generator file
	builder := &strings.Builder{}
	if err := t.Template.Execute(builder, data); err != nil {
		log.Println("t.Template.Execute() error:", err)
		return err
	}
	generatorStr := builder.String()

	// store generator file in jsnark-demo
	generatorFile, err := os.OpenFile("dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/"+t.FileName+".java", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Println("os.OpenFile() error:", err)
		return err
	}
	_, err = generatorFile.WriteString(generatorStr)
	if err != nil {
		log.Println("generatorFile.WriteString error:", err)
		generatorFile.Close()
		return err
	}
	generatorFile.Close()

	// debug
	log.Println("generator file has been written successfully.")

	// compile generator file
	cmd := exec.Command("bash", "-c", "javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep \".java$\")")
	cmd.Dir = "dependencies/jsnark-demo/JsnarkCircuitBuilder/"
	_, err = cmd.Output()
	if err != nil {
		log.Println("cmd.Run() error:", err)
		return err
	}

	// debug command output of compile
	// log.Println("compile java generator, output:", string(out))
	log.Println("java generator code has been compiled successfully.")

	// overwrite bin folder zk-build/jsnark
	cmd2 := exec.Command("cp", "-r", "dependencies/jsnark-demo/JsnarkCircuitBuilder/bin", "prover/zksnark_build/jsnark")
	cmd.Dir = "../"
	if err := cmd2.Run(); err != nil {
		log.Println("cmd2.Run() error:", err)
		return err
	}
	log.Println("compiled generator code has been copied successfully to prover folder..")

	return nil
}

func getComparatorGT(filename string) map[string]string {

	data := map[string]string{
		"GenName":                filename,
		"Import":                 "GTFloatThresholdComparatorGadget",
		"PrivateThresholdType":   "BigInteger",
		"ThresholdWireArraySize": "1",
		"ComparatorCall":         "GTFloatThresholdComparatorGadget",
		"SetThreshold":           "circuitEvaluator.setWireValue(thresholdValue[0], threshold)",
		"TestThreshold":          "new BigInteger(\"1406000\")",
		"GeneratorThreshold":     "new BigInteger(args[24])",
	}

	return data
}

func getComparatorLT(filename string) map[string]string {

	data := map[string]string{
		"GenName":                filename,
		"Import":                 "LTFloatThresholdComparatorGadget",
		"PrivateThresholdType":   "BigInteger",
		"ThresholdWireArraySize": "1",
		"ComparatorCall":         "LTFloatThresholdComparatorGadget",
		"SetThreshold":           "circuitEvaluator.setWireValue(thresholdValue[0], threshold)",
		"TestThreshold":          "new BigInteger(\"1406000\")",
		"GeneratorThreshold":     "new BigInteger(args[24])",
	}

	return data
}

func getComparatorEQ(filename string) map[string]string {

	data := map[string]string{
		"GenName":                filename,
		"Import":                 "EQFloatComparatorGadget",
		"PrivateThresholdType":   "String",
		"ThresholdWireArraySize": "floatStringLen",
		"ComparatorCall":         "EQFloatComparatorGadget",
		"SetThreshold":           "setWires2(thresholdValue, threshold, circuitEvaluator)",
		"TestThreshold":          "\"140.6000\"",
		"GeneratorThreshold":     "args[24]",
	}

	// sample_data := map[string]interface{}{
	// "Name":     "Bob",
	// "UserName": "bob92",
	// "Roles":    []string{"dbteam", "uiteam", "tester"},
	// }

	return data
}

func getTemplate1() string {
	return `
package examples.generators.transpiled;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.comparator.{{.Import}};
import examples.gadgets.comparator.JSONKeyValuePairComparatorGadget;
import examples.gadgets.kdc.KDCOPTGadget;

import java.math.BigInteger;

public class {{.GenName}} extends CircuitGenerator {
    private Wire[] HS;
    private Wire[] SHTSInnerHashOutput;
    private Wire[] output;
    //    private Wire[] SHTS;
    private Wire[] kfsInnerHashOutput;
    private Wire[] sfInnerHashOutput;
    private Wire[] dHSInnerHashOutput;
    private Wire[] MSInnerHashOutput;
    private Wire[] SATSInnerHashOutput;
    private Wire[] CATSInnerHashOutput;
    private Wire[] kSAPPKeyInnerHashOutput;
    private Wire[] kSAPPIVInnerHashOutput;
    private Wire[] kCAPPKeyInnerHashOutput;
    private Wire[] kCAPPIVInnerHashOutput;

    private Wire[] plaintextChunks;
    private Wire[] ciphertextChunks;

    private Wire[] circuitInputSF;
    private Wire[] seqCounter;

    private Wire[] thresholdValue;

    private int blockNr;
    private int startBlockIdx;
    private int keyValuePairLen;
    private int offsetKeyValuePair;
    private int offsetValue;
    private int floatStringLen;
    private int dotIdx;
    private String keyValueStartPattern;

    private String HSStr;
    private String SHTSInnerHashStr;
    private String kfsInnerHashStr;
    private String sfInnerHashStr;
    private String dHSInnerHashStr;
    private String MSHSInnerHashStr;
    private String SATSInnerHashStr;
    private String CATSInnerHashStr;
    private String kSAPPKeyInnerHashStr;
    private String kSAPPIVInnerHashStr;
    private String kCAPPKeyInnerHashStr;
    private String kCAPPIVInnerHashStr;
    private String plaintextStr;
    private String SFStr;
    private String SeqCounterStr;
    private String ciphertextStr;

    private {{.PrivateThresholdType}} threshold;

    private int compareMaxBitLength;

    public {{.GenName}}(String circuitName) {
	super(circuitName);
    }

    @Override
    protected void buildCircuit() {
	HS = createProverWitnessWireArray(32);
	SHTSInnerHashOutput = createInputWireArray(32);
	kfsInnerHashOutput = createInputWireArray(32);
	sfInnerHashOutput = createInputWireArray(32);
	dHSInnerHashOutput = createInputWireArray(32);
	MSInnerHashOutput = createInputWireArray(32);
	SATSInnerHashOutput = createInputWireArray(32);
	CATSInnerHashOutput = createInputWireArray(32);
	kSAPPKeyInnerHashOutput = createInputWireArray(32);
	kSAPPIVInnerHashOutput = createInputWireArray(32);
	kCAPPKeyInnerHashOutput = createInputWireArray(32);
	kCAPPIVInnerHashOutput = createInputWireArray(32);
	plaintextChunks = createProverWitnessWireArray(16*blockNr);

	circuitInputSF = createInputWireArray(32);
	ciphertextChunks = createInputWireArray(16*blockNr);
	seqCounter = createInputWireArray(8);

	// for equality check, change createInputWireArray to floatStringLen instead of 1
	thresholdValue = createInputWireArray({{.ThresholdWireArraySize}});

	Wire tmp;

	// key derivation circuit
	tmp = new KDCOPTGadget(HS, SHTSInnerHashOutput,  kfsInnerHashOutput, sfInnerHashOutput,
		dHSInnerHashOutput, MSInnerHashOutput, SATSInnerHashOutput,
		CATSInnerHashOutput, kSAPPKeyInnerHashOutput, kSAPPIVInnerHashOutput,
		kCAPPKeyInnerHashOutput, kCAPPIVInnerHashOutput, plaintextChunks,
		ciphertextChunks, circuitInputSF, seqCounter, startBlockIdx).getOutputWires()[0];

	// substring locator in plaintextChunks
	Wire[] keyValuePair = new Wire[keyValuePairLen];
	System.arraycopy(plaintextChunks, offsetKeyValuePair, keyValuePair,0,keyValuePair.length);
	String jsonKeyStr = convertASCIIStringToHexString(keyValueStartPattern);
	output = new JSONKeyValuePairComparatorGadget(plaintextChunks, plaintextChunks.length, keyValuePair, offsetKeyValuePair,
		keyValuePairLen, jsonKeyStr).getOutputWires();
	// verifies substring inclusing
	tmp = tmp.and(output[0]);

	// copy plaintextChunks into floatString for float comparison
	Wire[] floatString = new Wire[floatStringLen];
	System.arraycopy(plaintextChunks, offsetValue, floatString , 0, floatStringLen);

	// float comparator statement
	Wire compResult = new {{.ComparatorCall}}(floatString, floatStringLen, dotIdx,
		thresholdValue, compareMaxBitLength).getOutputWires()[0];

	// verify float comparator
	output[0] = tmp.and(compResult);

	makeOutputArray(output, "digest");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

	setWires(HS, HSStr, circuitEvaluator);
	setWires(SHTSInnerHashOutput, SHTSInnerHashStr, circuitEvaluator);
	setWires(kfsInnerHashOutput, kfsInnerHashStr, circuitEvaluator);
	setWires(sfInnerHashOutput, sfInnerHashStr, circuitEvaluator);
	setWires(dHSInnerHashOutput, dHSInnerHashStr, circuitEvaluator);
	setWires(MSInnerHashOutput, MSHSInnerHashStr, circuitEvaluator);
	setWires(SATSInnerHashOutput, SATSInnerHashStr, circuitEvaluator);
	setWires(CATSInnerHashOutput, CATSInnerHashStr, circuitEvaluator);
	setWires(kSAPPKeyInnerHashOutput, kSAPPKeyInnerHashStr, circuitEvaluator);
	setWires(kSAPPIVInnerHashOutput, kSAPPIVInnerHashStr, circuitEvaluator);
	setWires(kCAPPKeyInnerHashOutput, kCAPPKeyInnerHashStr, circuitEvaluator);
	setWires(kCAPPIVInnerHashOutput, kCAPPIVInnerHashStr, circuitEvaluator);
	setWires(plaintextChunks, plaintextStr, circuitEvaluator);
	setWires(circuitInputSF, SFStr, circuitEvaluator);
	setWires(seqCounter, SeqCounterStr, circuitEvaluator);
	setWires(ciphertextChunks, ciphertextStr, circuitEvaluator);
	// change threshold to setWires as well in case of EQ
	{{.SetThreshold}};

    }

    private void setWires2(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
	for (int i = 0; i < inputStr.length(); i++) {
	    circuitEvaluator.setWireValue(wires[i], BigInteger.valueOf(inputStr.charAt(i)));
	}
    }

    private void setWires(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
	for (int i = 0; i < inputStr.length()/2; i++) {
	    circuitEvaluator.setWireValue(wires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2), 16));
	}
    }

    public String convertASCIIStringToHexString(String asciiStr) {
	char[] ch = asciiStr.toCharArray();

	StringBuilder builder = new StringBuilder();
	for (char c : ch) {
	    int i = (int) c;
	    builder.append(Integer.toHexString(i));
	    if (builder.length() % 2 != 0) {
		builder.insert(builder.length()-1, '0');
	    }
	}
	return  builder.toString();
    }

    public static void main(String[] args) throws Exception {
	Config.hexOutputEnabled = true;
	{{.GenName}} generator = new {{.GenName}}("{{.GenName}}_Circuit");
	if (args.length == 0) {

//            // IBM example
	    generator.blockNr = 4;
	    generator.startBlockIdx = 4;
	    generator.keyValuePairLen = 59;
	    generator.offsetKeyValuePair = 0;
	    generator.offsetValue = 49;
	    generator.floatStringLen = 8;
	    generator.dotIdx = 3;
	    generator.keyValueStartPattern = "\"2022-07-08 14:55:00\": {\n            \"1. open\": \"";

	    generator.HSStr = "e9b1d92d1935f26a40d452ab0fd604881641ee97e142a82c5a434af04fb78c44";
	    generator.SHTSInnerHashStr = "499979f088b74f1055eed455f1d764590f0815ba2dc2b4fe009198223c012873";
	    generator.kfsInnerHashStr = "75295d4574e3c6b25766c693aa05b19c1ff5146d39e4abca35b77937f50b6e2f";
	    generator.sfInnerHashStr = "fc890bba1c455bbcab4e120b10cce69858e70565f7a3ae8c0553de9fd8c1187d";
	    generator.dHSInnerHashStr = "6d7d503805f5e0d9076cf4ecd57f00833da01b11d5798aaea131886fb2ed5fef";
	    generator.MSHSInnerHashStr = "4beff4e1f5b32c576642950a4426c84e31a7e76b442efd34839f1f6ecccaf05a";
	    generator.SATSInnerHashStr = "d14d6dd0c0a774ba5b807f8fccab48f076708e8c59abfaf76cc5215fb18a5863";
	    generator.CATSInnerHashStr = "9497b322fc7b44cf428b5aa230a5441dc7b0ff1dfa234b728f7a686b3777c5c7";
	    generator.kSAPPKeyInnerHashStr = "63c0311991de9a6e1c4a07aeb4cc3bbe4f3ea950eb19904f947e58c9457710f4";
	    generator.kSAPPIVInnerHashStr = "96045f763d4bb52e0a7fb070f0e5490ecf61cff25283b6594b24c875ab951100";
	    generator.kCAPPKeyInnerHashStr = "b39afe3258e35f68bbf1de379b78db390d5f761fae3030f92457515c5edbfe14";
	    generator.kCAPPIVInnerHashStr = "a75fcb710c29ee7c8bef8e538838b7327423f6d839778a748b4f8c710a020a47";
	    generator.plaintextStr = "22323032322d30372d30382031343a35353a3030223a207b0a20202020202020202020202022312e206f70656e223a20223134302e37393030222c0a20202020";
	    generator.SFStr = "f7deb8fb4674964bc55e769de43b2d53bf1c8a27274445c241d017752f80cada";
	    generator.SeqCounterStr = "000000000000000e";
	    generator.ciphertextStr = "604ee028a674c4f56b1b53f1849b91f32209075617af63ac849d5cbd167564ddfdcb0272c68b19e7f48a0bce6a3da430384f3f7812646678e0996c600738bb90";
	    generator.threshold = {{.TestThreshold}}; // new BigInteger("1406000"); // scaled 10x
	    // generator.threshold = "140.6000"; // scaled 10x
	    generator.compareMaxBitLength = 24;

//        // BTC localhost example
//            generator.blockNr = 2;
//            generator.startBlockIdx = 30;
//            generator.keyValuePairLen = 18;
//            generator.offsetKeyValuePair = 13;
//            generator.offsetValue = 22;
//            generator.floatStringLen = 7;
//            generator.dotIdx = 5;
//            generator.keyValueStartPattern = "\"price\":\"";
//
//            generator.HSStr = "04a58170602e72a980824fdc60865faf325e1a894b9c723cc5a423752996e0f6";
//            generator.SHTSInnerHashStr = "112b5850acb7fd75fe8f4092c356b569b8f02907eaebee4c0b0dc03886ac92f0";
//            generator.kfsInnerHashStr = "6383680126cb49d4ca6c8d92ec7aac8730c40435a44b324a3a7e2674ee76a61d";
//            generator.sfInnerHashStr = "4c077f3f34e1d3fb5238fb0e198f52b228f941be1efdbe787cdf665799dee674";
//            generator.dHSInnerHashStr = "48911e8a5b54e0185de7f933f8ee185632cde9fd88531183ec380cb43b7c1198";
//            generator.MSHSInnerHashStr = "76c9bf8620d4e3faa1ace4bda0a233f0e4c993c1fd8c474e3c987976ef35eb46";
//            generator.SATSInnerHashStr = "164c587e1fab57439a068e264ad2c80577ba34a611801991b72b3cd589ca3e0e";
//            generator.CATSInnerHashStr = "a17cb4914037982799c110e2617dd9a7f0687ee094efb9be7da668c021a1f1f2";
//            generator.kSAPPKeyInnerHashStr = "26f26a24462563ab93d62f4ffbf23789dc1f3412633b8bbf8c1509c04b162358";
//            generator.kSAPPIVInnerHashStr = "aef0e12dd3579fa59c82ba2921723281e13a0343a55886dd141193183b1491d4";
//            generator.kCAPPKeyInnerHashStr = "2e651e2f16feadf0b5e55345a652353420cec11b87052bd9d81542a905fa5135";
//            generator.kCAPPIVInnerHashStr = "acc8cfdf651b58d2b97f738e284f0369ebb13ddbe4531783dda170abf07d62ca";
//            generator.plaintextStr = "302c353631204575726f227d2c227072696365223a2233383030322e32222c22";
//            generator.SFStr = "4294b43a9f2579c43b951a65ae57431804be96c9c71613ea5eeebfc83a91fbf5";
//            generator.SeqCounterStr = "0000000000000000";
//            generator.ciphertextStr = "74ddda545b8233a6f41fb7fc70669c30249282ca8271a47e7f57c860943caac9";
//            generator.threshold = new BigInteger("380021"); // scaled 10x
//            generator.compareMaxBitLength = 20;
	} else {
	    generator.blockNr = Integer.parseInt(args[0]);
	    generator.startBlockIdx = Integer.parseInt(args[1]);
	    generator.keyValuePairLen = Integer.parseInt(args[2]);
	    generator.offsetKeyValuePair = Integer.parseInt(args[3]);
	    generator.offsetValue = Integer.parseInt(args[4]);
	    generator.floatStringLen = Integer.parseInt(args[5]);
	    generator.dotIdx = Integer.parseInt(args[6]);
	    generator.keyValueStartPattern = args[7];
	    generator.HSStr = args[8];
	    generator.SHTSInnerHashStr = args[9];
	    generator.kfsInnerHashStr = args[10];
	    generator.sfInnerHashStr = args[11];
	    generator.dHSInnerHashStr = args[12];
	    generator.MSHSInnerHashStr = args[13];
	    generator.SATSInnerHashStr = args[14];
	    generator.CATSInnerHashStr = args[15];
	    generator.kSAPPKeyInnerHashStr = args[16];
	    generator.kSAPPIVInnerHashStr = args[17];
	    generator.kCAPPKeyInnerHashStr = args[18];
	    generator.kCAPPIVInnerHashStr = args[19];
	    generator.plaintextStr = args[20];
	    generator.SFStr = args[21];
	    generator.SeqCounterStr = args[22];
	    generator.ciphertextStr = args[23];
	    // change threshold in EQ case to just args[24];
	    generator.threshold = {{.GeneratorThreshold}}; // scaled 10x
	    // generator.compareMaxBitLength = Integer.parseInt(args[25]);
	    generator.compareMaxBitLength = 126;
	}
	generator.generateCircuit();
	generator.evalCircuit();
	generator.prepFiles();
	// generator.runLibsnark();
    }
}
`
}
