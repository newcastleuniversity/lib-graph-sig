package eu.prismacloud.primitives.topocert;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.nio.file.ReadOnlyFileSystemException;
import java.util.Collections;
import java.util.Iterator;
import java.util.Vector;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import jargs.gnu.CmdLineParser;


public class Topocert {

	//  public abstract void graphEncodingSetup(IGraph graph, KeyGenParameters params);

	//    ArrayList<IVertex> vertices = new ArrayList<IVertex>();
	//            ArrayList<IEdge> edges = new ArrayList<IEdge>();
	//            ArrayList<ILabel> labels = new ArrayList<ILabel>();
	//    IGraph graphEnc = new GSGraph(vertices, edges, labels);
	//    IParams encParams = new EncParams(2048, 1632, 256, 256, 1, 597, 120, 2724, 80, 256, 80, 80 ,
	// 1000, 120, 50000, 256, 16);
	//            Topocert tpc = new Topocert();
	//
	//            tpc.setup(graphEnc, encParams);

	private KeyGenParameters keyGenParams;
	private GraphEncodingParameters graphEncParams;
	private FilePersistenceUtil persistenceUtil;
	private ExtendedPublicKey epk;

	public Topocert() {

	}

	public static void main(String[] argv) {
		TopocertCmdLineParser parser = new TopocertCmdLineParser();

		try {
			parser.parse(argv);
		} catch (CmdLineParser.UnknownOptionException e) {
			System.err.println(e.getMessage());
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		} catch (CmdLineParser.IllegalOptionValueException e) {
			System.err.println(e.getMessage());
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		}

		// Boolean Options
		Boolean keygenMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.KEYGEN);
		Boolean signMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.SIGN);
		Boolean receiveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.RECEIVE);
		Boolean proveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.PROVE);
		Boolean verifyMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.VERIFY);

		Boolean offerHelp = (Boolean) parser.getOptionValue(TopocertCmdLineParser.HELP);

		// String Options
		String graphFilename = (String) parser.getOptionValue(TopocertCmdLineParser.GRAPHFILENAME, TopocertDefaultOptionValues.DEF_GRAPH);
		String paramsFilename = (String) parser.getOptionValue(TopocertCmdLineParser.KEYGENPARAMS, TopocertDefaultOptionValues.DEF_KEYGEN_PARAMS);
		String encodingFilename = TopocertDefaultOptionValues.DEF_COUNTRY_ENCODING;

		String signerKeyFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_SKP);
		String signerPKFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_PK);
		String epkFilename = (String) parser.getOptionValue(TopocertCmdLineParser.EPK, TopocertDefaultOptionValues.DEF_EPK);

		// Integer Options: Zero or Multiple Queries
		@SuppressWarnings("unchecked")
		Vector<Integer> queryValues = (Vector<Integer>) parser.getOptionValues(TopocertCmdLineParser.GEOSEPQUERY);

		// Initialize Topocert and Read Parameters
		Topocert topocert = new Topocert();
		topocert.readParams(paramsFilename);

		//
		// Main Behavior Branching
		//
		if (offerHelp != null && offerHelp.booleanValue()) {
			parser.printUsage();
			System.exit(0);
		} else if (keygenMode != null && keygenMode.booleanValue()) {
			// Initialize TOPOCERT keygen
			System.out.println("Entering TOPOCERT key generation...");
			System.out.println("  Designated signer keypair file: " + signerKeyFilename);
			System.out.println("  Designated extended public key file: " + epkFilename);

			try {
				topocert.keygen(signerKeyFilename, signerPKFilename, epkFilename);
			} catch (IOException e) {
				System.err.println("The TOPOCERT keys could not be written to file.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_IOERR);
			} catch (EncodingException e) {
				System.err.println("The TOPOCERT graph encoding could not be setup.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_ENCERR);
			}

			System.exit(0);
		} else if (signMode != null && signMode.booleanValue()) {
			// Initialize signing, with specified signer graph file.
			System.out.println("Entering TOPOCERT Sign mode...");
			System.out.println("  Using signer keypair from file: " + signerKeyFilename);

			SignerKeyPair skp = null;
			System.out.print("  Reading signer keypair...");
			try {
				skp = topocert.readSignerKeyPair(signerKeyFilename);
			} catch(IOException e) {
				System.err.println("The TOPOCERT signer key pair could not be read.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_CRITFILE);
			} catch (ClassNotFoundException e) {
				System.err.println("The TOPOCERT signer key pair does not correspond the current class.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_CRITERR);
			}
			System.out.println("   [done]\n");

			topocert.sign(skp, graphFilename);

			System.exit(0);
		} else if (receiveMode != null && receiveMode.booleanValue()) {
			// Initialize receiving of a signature.
			System.out.println("Entering TOPOCERT Receive mode...");
			System.out.println("  Using Signer's extended public key: " + epkFilename);
			
			topocert.readEPK(epkFilename);
			
			topocert.receive();

			System.exit(0);
		} else if (proveMode != null && proveMode.booleanValue()) {
			// Initialize proving
			System.out.println("Entering TOPOCERT Prove mode...");
			System.out.println("  Using Signer's extended public key: " + epkFilename);
			
			topocert.readEPK(epkFilename);
			
			topocert.prove(graphFilename);

			System.exit(0);
		} else if (verifyMode != null && verifyMode.booleanValue()) {
			// Initialize verifying, specifying queries
			if (queryValues == null || queryValues.isEmpty() || queryValues.size() < 2) {
				System.err.println("In Verify mode, please name at least two vertices with the -q/--query option.\n");
				parser.printUsage();
				System.exit(TopocertErrorCodes.EX_USAGE);
			}
			System.out.println("Entering TOPOCERT Verify mode...");
			System.out.println("  Using Signer's extended public key: " + epkFilename);
			System.out.print("  Queried vertices: [ ");
			for (Iterator<Integer> iterator = queryValues.iterator(); iterator.hasNext();) {
				Integer queriedVertex = (Integer) iterator.next();
				System.out.print(queriedVertex);
				if (iterator.hasNext()) System.out.print(", ");
			}
			System.out.println(" ].");
			
			topocert.readEPK(epkFilename);
			
			topocert.verify(queryValues);

			System.exit(0);
		} else {
			System.err.println("Please specify a mode to operate in.\n");
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		}

		System.exit(0);
	}



	void readParams(String paramsFilename) {
		System.out.print("Reading parameters from file: " + paramsFilename +"...");
		try {
			readKeyGenParams(paramsFilename);
		} catch (Exception e) {
			System.err.println("The TOPOCERT keygen and graph encoding "
					+ "parameters could not be parsed from file: " + paramsFilename + ".");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CONFIG);
		}
		System.out.println("   [done]");
		System.out.println("  Setup for key bitlength: " + getKeyGenParams().getL_n() + "\n");
	}

	void readKeyGenParams(String paramsFilename) {
		JSONParameters parameters = new JSONParameters(paramsFilename);
		keyGenParams = parameters.getKeyGenParameters();
		graphEncParams = parameters.getGraphEncodingParameters();
		persistenceUtil = new FilePersistenceUtil();
		//		String defSignerKeyFile = "SignerKeyPair-" + keyGenParams.getL_n() + ".ser";
		//		String defEpkFile = "ExtendedPublicKey-" + keyGenParams.getL_n() + ".ser";
	}

	SignerKeyPair readSignerKeyPair(String signerKeyPairFilename) throws
	IOException, ClassNotFoundException {

		SignerKeyPair signerKeyPair = (SignerKeyPair) persistenceUtil.read(signerKeyPairFilename);

		return signerKeyPair;
	}

	ExtendedPublicKey readExtendedPublicKey(String epkFilename) throws
	IOException, ClassNotFoundException {

		this.epk =
		           (ExtendedPublicKey) persistenceUtil.read(epkFilename);

		return epk;
	}
	
	void readEPK(String epkFilename) {
		System.out.print("  Reading extended public key...");
		try {
			readExtendedPublicKey(epkFilename);
		} catch(IOException e) {
			System.err.println("The TOPOCERT extended public keu could not be read.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CRITFILE);
		} catch (ClassNotFoundException e) {
			System.err.println("The TOPOCERT extended public key does not correspond the current class.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]\n");
		System.out.println("  Extended Public Key holds " + epk.getBases().size() + " graph encoding bases.");
	}
	
	
	void keygen(String signerKeyPairFilename, String signerPKFilename, String epkFilename) throws IOException, EncodingException {
		// Establishing Signer Key Pair First
		SignerKeyPair gsk = new SignerKeyPair();
		System.out.print("  Keygen - Stage I:   Generating SRSA Signer key pair.");
		gsk.keyGen(keyGenParams);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage I:   Writing new Signer KeyPair...");
		persistenceUtil.write(gsk, signerKeyPairFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage I:   Writing new Signer PublicKey...");
		persistenceUtil.write(gsk.getPublicKey(), signerPKFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage II:  Generating bases for encoding...");
		ExtendedKeyPair ekp = new ExtendedKeyPair(gsk, graphEncParams, keyGenParams);
		ekp.generateBases();
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage II:  Setting up geo-location encoding...");
		ekp.setupEncoding();
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage III: Finalizing extended keypair...");
		ekp.createExtendedKeyPair();
		System.out.println("   [done]");

		System.out.print("  Keygen: - Stage III: Writing new ExtendedPublicKey...");
		this.epk = ekp.getExtendedPublicKey();
		persistenceUtil.write(ekp.getExtendedPublicKey(), epkFilename);
		System.out.println("   [done]");

		System.out.println("  Keygen: Completed.");
	}

	void sign(SignerKeyPair skp, String graphFilename) {
		System.out.println("  Sign: Hosting interactive signing for graph: " + graphFilename + "...");
		
		System.out.println("  Sign: Completed");
	}
	
	void receive() {
		System.out.println("  Receive: Initializing client communication for graph signing...");
		
		System.out.println("  Receive: Completed");
	}
	
	void prove(String graphFilename) {
		System.out.println("  Prove: Hosting prover for certified graph " + graphFilename + "...");
		
		System.out.println("  Prove: Completed");
	}
	
	void verify(Vector<Integer> vertexQueries) {
		System.out.println("  Verify: Initializing client communication for geo-location verification...");
		
		System.out.println("  Verify: Completed");
	}




	public KeyGenParameters getKeyGenParams() {
		return this.keyGenParams;
	}
}
