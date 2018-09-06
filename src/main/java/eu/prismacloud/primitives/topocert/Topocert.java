package eu.prismacloud.primitives.topocert;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Vector;

import org.jgrapht.io.ImportException;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.orchestrator.RecipientOrchestrator;
import eu.prismacloud.primitives.zkpgs.orchestrator.SignerOrchestrator;
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
		// String encodingFilename = TopocertDefaultOptionValues.DEF_COUNTRY_ENCODING;

		String signerKeyFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_SKP);
		String signerPKFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_PK);
		String ekpFilename = TopocertDefaultOptionValues.DEF_EKP;
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
				topocert.keygen(signerKeyFilename, ekpFilename, signerPKFilename, epkFilename);
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
			System.out.println("  Using extended keypair from file: " + ekpFilename);

			ExtendedKeyPair ekp = null;
			System.out.print("  Establishing extended signer keypair...");
			try {
				ekp = topocert.readExtendedKeyPair(ekpFilename);
			} catch(IOException e) {
				System.err.println("The TOPOCERT extended signer key pair could not be read.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_CRITFILE);
			} catch (ClassNotFoundException e) {
				System.err.println("The TOPOCERT extended signer key pair does not correspond the current class.");
				System.err.println(e.getMessage());
				System.exit(TopocertErrorCodes.EX_CRITERR);
			}
			System.out.println("   [done]\n");

			topocert.sign(ekp, graphFilename);

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

	ExtendedKeyPair readExtendedKeyPair(String extendedKeyPairFilename) throws
	IOException, ClassNotFoundException {


		ExtendedKeyPair extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFilename);

		return extendedKeyPair;
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


	void keygen(String signerKeyPairFilename, String ekpFilename, String signerPKFilename, String epkFilename) throws IOException, EncodingException {
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

		System.out.print("  Keygen: - Stage III: Writing new ExtendedKeyPair...");
		persistenceUtil.write(ekp, ekpFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen: - Stage III: Writing new ExtendedPublicKey...");
		this.epk = ekp.getExtendedPublicKey();
		persistenceUtil.write(ekp.getExtendedPublicKey(), epkFilename);
		System.out.println("   [done]");

		System.out.println("  Keygen: Completed.");
	}

	void sign(ExtendedKeyPair ekp, String graphFilename) {
		System.out.println("  Sign: Hosting interactive signing for graph: " + graphFilename + "...");
		SignerOrchestrator signer = new SignerOrchestrator(ekp);
		// TODO How does the signer get the graph as input?!

		try {
			signer.init();
		} catch (IOException e) {
			System.err.println("The TOPOCERT Signer could not establish a connection to the Recipient in Round 0.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOHOST);
		}

		System.out.print("  Sign - Round 0: Starting round0: Sending nonce...");
		try {
			signer.round0();
		} catch (IOException e) {
			System.err.println("The TOPOCERT Signer could not send the nonce to the Recipient in Round 0.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");


		System.out.print("  Sign - Round 2: Waiting for the Recipient's commitment...");
		try {
			signer.round2();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("The TOPOCERT Signer could not compute the Fiat-Shamir hash in Round 2 due to missing hash algorithm.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CRITERR);
		} catch (ImportException e) {
			System.err.println("The TOPOCERT Signer not import the GraphML file in Round 2.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOINPUT);
		} catch (IOException e) {
			System.err.println("The TOPOCERT Signer could not read the GraphML file in Round 2.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_IOERR);
		} catch (ProofStoreException e) {
			System.err.println("The TOPOCERT Signer not store/retrieve elements in the ProofStore in Round 2.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_DATAERR);
		} catch (VerificationException e) {
			System.err.println("The TOPOCERT Signer could not verify the proof of representation of the Recipient's commitment in Round 2.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_VERIFY);
		} catch (EncodingException e) {
			System.err.println("The TOPOCERT Signer could not encode the graph in Round 2.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_ENCERR);
		}
		System.out.println("   [done]");

		
		
		try {
			signer.close();
		} catch (IOException e) {
			System.err.println("The TOPOCERT Signer failed to close the connection to the Recipient soundly.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_IOERR);
		}
		
		System.out.println("  Sign: Completed");
	}

	void receive() {
		System.out.println("  Receive: Initializing client communication for graph signing...");

		RecipientOrchestrator recipient = new RecipientOrchestrator(epk);
		
		try {
			recipient.init();
		} catch (IOException e) {
			System.err.println("The TOPOCERT Recipient could not open a server socket for the Signer in Round 0.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOHOST);
		}

		System.out.print("  Receive - Round 1: Waiting the Signer's nonce...");
		try {
			recipient.round1();
		} catch (ProofStoreException e) {
			System.err.println("The TOPOCERT Recipient could not complete its commitment in Round 1.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			System.err.println("The TOPOCERT Recipient could not receive the nonce from the Signer in Round 1.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOHOST);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("The TOPOCERT Recipient could not compute the Fiat-Shamir hash in Round 2 due to missing hash algorithm.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]");

		System.out.print("  Receive - Round 3: Waiting for the Signer's pre-signature...");
		try {
			recipient.round3();
		} catch (VerificationException e) {
			System.err.println("The TOPOCERT Recipient could not verify the Signer's proof on the presented new signature in Round 3.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_VERIFY);
		} catch (ProofStoreException e) {
			System.err.println("The TOPOCERT Recipient could not access expected data in the ProofStore in Round 3.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			System.err.println("The TOPOCERT Recipient could not receive the signature from the Signer in Round 3.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_NOHOST);
		}

		try {
			recipient.close();
		} catch (IOException e) {
			System.err.println("The TOPOCERT Recipient failed to close the connection to the Signer soundly.");
			System.err.println(e.getMessage());
			System.exit(TopocertErrorCodes.EX_IOERR);
		}
		
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
