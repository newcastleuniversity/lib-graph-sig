package uk.ac.ncl.cascade.topographia;

import jargs.gnu.CmdLineParser;
import org.jgrapht.io.ImportException;
import uk.ac.ncl.cascade.binding.*;
import uk.ac.ncl.cascade.hashToPrime.HashToPrimeElimination;
import uk.ac.ncl.cascade.hashToPrime.NaorReingoldPRG;
import uk.ac.ncl.cascade.hashToPrime.SquareHashing;
import uk.ac.ncl.cascade.zkpgs.encoding.IGraphEncoding;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.*;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.ProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.VerifierOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues.DEF_PSEUDONYMS;
import static uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues.DEF_PSEUDONYMS_PRIMES;
import static uk.ac.ncl.cascade.zkpgs.DefaultValues.CLIENT;
import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER;


public class Topographia {
	private static final int MODULUS_LENGTH = 220;
	private static FilePersistenceUtil persistenceUtil;
	private static Map<String, BigInteger> pseudonymPrimes;
	private KeyGenParameters keyGenParams;
	private GraphEncodingParameters graphEncParams;
	private ExtendedPublicKey epk;
	private static boolean verbose = false;
	private KeyGenParameters hKeyGenParameters;
	private PrimeOrderGroup group;

	private BigInteger e_i;

	public Topographia() {

	}

	public static void main(String[] argv) throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException, ImportException, EncodingException, InterruptedException {
		TopographiaCmdLineParser parser = new TopographiaCmdLineParser();

		try {
			parser.parse(argv);
		} catch (CmdLineParser.UnknownOptionException e) {
			System.err.println(e.getMessage() + "\n");
			parser.printUsage();
			System.exit(TopographiaErrorCodes.EX_USAGE);
		} catch (CmdLineParser.IllegalOptionValueException e) {
			System.err.println(e.getMessage() + "\n");
			parser.printUsage();
			System.exit(TopographiaErrorCodes.EX_USAGE);
		}

		// Boolean Options
		Boolean keygenMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.KEYGEN);
		Boolean signMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.SIGN);
		Boolean receiveMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.RECEIVE);
		Boolean proveMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.PROVE);
		Boolean verifyMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.VERIFY);

		Boolean signBindingMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.SIGN_BINDINGS);
		Boolean receiveBindingMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.RECEIVE_BINDINGS);
		Boolean proveBindingMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.PROVE_BINDINGS);
		Boolean verifyBindingMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.VERIFY_BINDINGS);

		Boolean verboseLogs = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.VERBOSE);

		Boolean bindingCredMode = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.VERTEX_CREDENTIAL);

		Boolean offerHelp = (Boolean) parser.getOptionValue(TopographiaCmdLineParser.HELP);

		// String Options
		String graphFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.GRAPHFILENAME, TopographiaDefaultOptionValues.DEF_GRAPH);

		String paramsFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.KEYGENPARAMS, TopographiaDefaultOptionValues.DEF_KEYGEN_PARAMS);
		// String encodingFilename = TopocertDefaultOptionValues.DEF_COUNTRY_ENCODING;

		String signerKeyFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.SIGNERKP, TopographiaDefaultOptionValues.DEF_SKP);
		String signerPKFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.SIGNERKP, TopographiaDefaultOptionValues.DEF_PK);
		String ekpFilename = TopographiaDefaultOptionValues.DEF_EKP;
		String epkFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.EPK, TopographiaDefaultOptionValues.DEF_EPK);
		String sigmaFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.GSSIGNATURE, TopographiaDefaultOptionValues.DEF_GSSIGNATURE);
		String vertexCredFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.VCRED, TopographiaDefaultOptionValues.DEF_VCRED);
		String pseudonymFilename = (String) parser.getOptionValue(TopographiaCmdLineParser.PSEUDONYM_FILE, DEF_PSEUDONYMS);
		String pseudonym = (String) parser.getOptionValue(TopographiaCmdLineParser.NYM, TopographiaDefaultOptionValues.DEF_NYM);
		String hostAddress = (String) parser.getOptionValue(TopographiaCmdLineParser.HOST_ADDRESS, TopographiaDefaultOptionValues.DEF_HOST_ADDRESS);


		// Integer Options: Zero or Multiple Queries
		@SuppressWarnings("unchecked")
		Vector<Integer> queryValues = (Vector<Integer>) parser.getOptionValues(TopographiaCmdLineParser.GEOSEPQUERY);
		Integer portNumber = (Integer) parser.getOptionValue(TopographiaCmdLineParser.PORT_NUMBER, TopographiaDefaultOptionValues.DEF_PORT_NUMBER);
		// User needing help?
		if (offerHelp != null && offerHelp.booleanValue()) {
			parser.printUsage();
			System.exit(0);
		}

		if (verboseLogs != null && verboseLogs.booleanValue()) {
			Topographia.verbose = true;
		}

		// Checking that there is exactly one mode specified.
		int numberOfModes = 0;
		if (keygenMode != null && keygenMode.booleanValue()) numberOfModes++;
		if (signMode != null && signMode.booleanValue()) numberOfModes++;
		if (receiveMode != null && receiveMode.booleanValue()) numberOfModes++;
		if (proveMode != null && proveMode.booleanValue()) numberOfModes++;
		if (verifyMode != null && verifyMode.booleanValue()) numberOfModes++;
		// binding related modes
		if (signBindingMode != null && signBindingMode.booleanValue()) numberOfModes++;
		if (receiveBindingMode != null && receiveBindingMode.booleanValue()) numberOfModes++;
		if (proveBindingMode != null && proveBindingMode.booleanValue()) numberOfModes++;
		if (verifyBindingMode != null && verifyBindingMode.booleanValue()) numberOfModes++;
		if (numberOfModes == 0 || numberOfModes > 1) {
			System.err.println("Please specify exactly one mode for TOPOGRAPHIA to run in.\n");
			parser.printUsage();
			System.exit(TopographiaErrorCodes.EX_USAGE);
		}

		// Initialize Topographia and Read Parameters
		Topographia topographia = new Topographia();
		topographia.readParams(paramsFilename);
		persistenceUtil = new FilePersistenceUtil();


		//
		// Main Behavior Branching
		//
		try {
			List<String> pslist;
			if (keygenMode != null && keygenMode.booleanValue()) {
				// Initialize TOPOGRAPHIA keygen
				System.out.println("Entering TOPOGRAPHIA key generation...");
				System.out.println("  Designated signer keypair file: " + signerKeyFilename);
				System.out.println("  Designated extended public key file: " + epkFilename);

				try {
					topographia.keygen(signerKeyFilename, ekpFilename, signerPKFilename, epkFilename);
				} catch (IOException e) {
					handleException(e, "The TOPOGRAPHIA keys could not be written to file.",
							TopographiaErrorCodes.EX_IOERR);
				} catch (EncodingException e) {
					handleException(e, "The TOPOGRAPHIA graph encoding could not be setup.",
							TopographiaErrorCodes.EX_ENCERR);
				}

				System.exit(0);
			} else if (signMode != null && signMode.booleanValue()) {
				// Initialize signing, with specified signer graph file.
				System.out.println("Entering TOPOGRAPHIA Sign mode...");
				System.out.println("  Using extended keypair from file: " + ekpFilename);

				ExtendedKeyPair ekp = null;
				System.out.print("  Establishing extended signer keypair...");
				try {
					ekp = topographia.readExtendedKeyPair(ekpFilename);
				} catch (IOException e) {
					handleException(e, "The TOPOGRAPHIA extended signer key pair could not be read.",
							TopographiaErrorCodes.EX_CRITFILE);
				} catch (ClassNotFoundException e) {
					handleException(e, "The TOPOGRAPHIA extended signer key pair does not correspond the current class.",
							TopographiaErrorCodes.EX_CRITERR);
				}
				if (ekp == null) {
					System.err.println("Extended signer keypair could not be established; returned null.");
					System.exit(TopographiaErrorCodes.EX_SOFTWARE);
				}
				System.out.println("   [done]\n");

				if (bindingCredMode != null && bindingCredMode) {
					pseudonymPrimes = new LinkedHashMap<String, BigInteger>();
					topographia.signbc(ekp, pseudonym, hostAddress, portNumber);
					persistenceUtil.writeFileLines("pseudonymPrimes.txt", pseudonymPrimes);
				} else {
					topographia.sign(ekp, graphFilename, hostAddress, portNumber);
				}

				System.exit(0);

			} else if (signBindingMode != null && signBindingMode.booleanValue()) {
				// Initialize signing, with specified signer graph file.
				System.out.println("Entering TOPOGRAPHIA Sign mode...");
				System.out.println("  Using extended keypair from file: " + ekpFilename);

				ExtendedKeyPair ekp = null;
				System.out.print("  Establishing extended signer keypair...");
				try {
					ekp = topographia.readExtendedKeyPair(ekpFilename);
				} catch (IOException e) {
					handleException(e, "The TOPOGRAPHIA extended signer key pair could not be read.",
							TopographiaErrorCodes.EX_CRITFILE);
				} catch (ClassNotFoundException e) {
					handleException(e, "The TOPOGRAPHIA extended signer key pair does not correspond the current class.",
							TopographiaErrorCodes.EX_CRITERR);
				}
				if (ekp == null) {
					System.err.println("Extended signer keypair could not be established; returned null.");
					System.exit(TopographiaErrorCodes.EX_SOFTWARE);
				}
				System.out.println("   [done]\n");
				System.out.println(" Establishing possession proofs for binding credentials for vertices in the graph...");

				topographia.readEPK(epkFilename);
				topographia.signBindings(ekp, graphFilename, pseudonymPrimes, hostAddress, portNumber);

				System.exit(0);

			} else if (receiveMode != null && receiveMode.booleanValue()) {
				// Initialize receiving of a signature.
				System.out.println("Entering TOPOGRAPHIA Receive mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topographia.readEPK(epkFilename);
				if (bindingCredMode != null && bindingCredMode) {

					pslist = persistenceUtil.readFileLines(pseudonymFilename);
					for (int i = 0; i < pslist.size(); i++) {

						topographia.receivebc(graphFilename, "vertexCred" + "_" + String.valueOf(i) + ".ser", i, hostAddress, portNumber);
					}
				} else {
					topographia.receive(graphFilename, sigmaFilename, hostAddress, portNumber);

				}

				System.exit(0);
			} else if (receiveBindingMode != null && receiveBindingMode.booleanValue()) {

				System.out.println("Entering TOPOGRAPHIA Receive binding  mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topographia.readEPK(epkFilename);
				pslist = persistenceUtil.readFileLines(pseudonymFilename);
				topographia.receiveBindings(graphFilename, sigmaFilename, pslist, hostAddress, portNumber);
				System.exit(0);

			} else if (proveMode != null && proveMode.booleanValue()) {
				// Initialize proving
				System.out.println("Entering TOPOGRAPHIA Prove mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topographia.readEPK(epkFilename);

				if (bindingCredMode != null && bindingCredMode) {

					pslist = persistenceUtil.readFileLines(pseudonymFilename);
					for (int i = 0; i < pslist.size(); i++) {
						topographia.provevc(pseudonymFilename, "vertexCred" + "_" + String.valueOf(i) + ".ser", hostAddress, portNumber);
						portNumber++;
					}
				} else {
					topographia.prove(graphFilename, sigmaFilename, hostAddress, portNumber);
				}

				System.exit(0);
			} else if (proveBindingMode != null && proveBindingMode.booleanValue()) {
				// Initialize proving
				System.out.println("Entering TOPOGRAPHIA Prove binding mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topographia.readEPK(epkFilename);

				topographia.proveBindings(graphFilename, sigmaFilename, hostAddress, portNumber);

				System.exit(0);
			} else if (verifyMode != null && verifyMode.booleanValue()) {

				if (bindingCredMode == null || !bindingCredMode) {
					// Initialize verifying, specifying queries
					if (queryValues == null || queryValues.isEmpty() || queryValues.size() < 2) {
						System.err.println("In Verify mode, please name at least two vertices with the -q/--query option.\n");
						parser.printUsage();
						System.exit(TopographiaErrorCodes.EX_USAGE);
					}
					System.out.println("Entering TOPOGRAPHIA Verify mode...");
					System.out.println("  Using Signer's extended public key: " + epkFilename);
					System.out.print("  Queried vertices: [ ");
					for (Iterator<Integer> iterator = queryValues.iterator(); iterator.hasNext(); ) {
						Integer queriedVertex = (Integer) iterator.next();
						System.out.print(queriedVertex);
						if (iterator.hasNext()) System.out.print(", ");
					}
					System.out.println(" ].");
				}
				topographia.readEPK(epkFilename);
				if (bindingCredMode != null && bindingCredMode) {
					pslist = persistenceUtil.readFileLines(pseudonymFilename);
					for (int i = 0; i < pslist.size(); i++) {
						topographia.verifyvc(hostAddress, portNumber);
					}
				} else {
					topographia.verify(queryValues, hostAddress, portNumber);
				}

				System.exit(0);
			} else if (verifyBindingMode != null && verifyBindingMode.booleanValue()) {
				topographia.readEPK(epkFilename);
				System.out.println("Entering TOPOGRAPHIA Verify binding mode...");
				topographia.verifyBindings(hostAddress, portNumber);

				System.exit(0);
			} else {
				System.err.println("Please specify a mode to operate in.\n");
				parser.printUsage();
				System.exit(TopographiaErrorCodes.EX_USAGE);
			}

			// Severe Error Conditions
		} catch (IllegalStateException e) {
			handleException(e, "TOPOGRAPHIA detected an illegal state and is aborting "
					+ "the protocol run.", TopographiaErrorCodes.EX_STATE);
		} catch (IllegalArgumentException e) {
			handleException(e, "TOPOGRAPHIA detected a call with an illegal argument "
					+ "and is aborting the protocol run.", TopographiaErrorCodes.EX_SOFTWARE);
		} catch (NotImplementedException e) {
			handleException(e, "TOPOGRAPHIA detected that a method was called that has "
					+ "not been released for production yet.", TopographiaErrorCodes.EX_SOFTWARE);
		} catch (RuntimeException e) {
			handleException(e, "TOPOGRAPHIA detected a runtime exception "
					+ "and is aborting the protocol run.", TopographiaErrorCodes.EX_SOFTWARE);
		} catch (GSInternalError e) {
			handleException(e, "TOPOGRAPHIA detected an unexpcected, critical internal error "
					+ "that it could not recover from.", TopographiaErrorCodes.EX_CRITERR);
		}

		System.exit(0);
	}


	void readParams(String paramsFilename) {
		System.out.print("Reading parameters from file: " + paramsFilename + "...");
		try {
			readKeyGenParams(paramsFilename);
		} catch (Exception e) {
			handleException(e, "The TOPOGRAPHIA keygen and graph encoding "
							+ "parameters could not be parsed from file: " + paramsFilename + ".",
					TopographiaErrorCodes.EX_CONFIG);
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
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA extended public keu could not be read.",
					TopographiaErrorCodes.EX_CRITFILE);
		} catch (ClassNotFoundException e) {
			handleException(e, "The TOPOGRAPHIA extended public key does not correspond the current class.",
					TopographiaErrorCodes.EX_CRITERR);
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

		// TODO offer a command line option to add custom encodings
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


	private void setupHashToPrime() throws IOException, ClassNotFoundException {
		hKeyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);
		persistenceUtil = new FilePersistenceUtil();

		File f = new File(TopographiaDefaultOptionValues.DEF_GROUP_FILENAME);
		boolean isFile = f.exists();

		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(TopographiaDefaultOptionValues.DEF_GROUP_FILENAME);
		} else {

			SafePrime safePrime = CryptoUtilsFacade.computeRandomSafePrime(hKeyGenParameters);
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			GroupElement generator = group.createGenerator();
			persistenceUtil.write(group, TopographiaDefaultOptionValues.DEF_GROUP_FILENAME);
		}


	}

	private BigInteger computeHashToPrime(String nym) {
		BigInteger sqPrime = group.getModulus();

		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());

		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);

		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, hKeyGenParameters);

		BigInteger message = new BigInteger(nym, 16);

		BigInteger res = htp.computeSquareHash(message);
		Assert.notNull(res, "Cannot compute square hash of input message");
		return htp.computePrime(res);
	}

	void sign(ExtendedKeyPair ekp, String graphFilename, String hostAddress, int portNumber) throws IOException, ClassNotFoundException, ImportException, EncodingException {
		System.out.println("  Sign: Acts as client for interactive signing of graph: " + graphFilename + ".");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		SignerOrchestrator signer = new SignerOrchestrator(graphFilename, ekp, messageGateway);

		System.out.print("  Sign: Initializing the Signer role...");
		try {
			signer.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not establish a connection to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Sign - Round 0: Starting round0: Sending nonce...");
		try {
			signer.round0();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not send the nonce to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();
		System.out.print("  Sign - Round 2: Waiting for the Recipient's commitment...");
		try {
			signer.round2();
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not read the GraphML file in Round 2.",
					TopographiaErrorCodes.EX_IOERR);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Signer not store/retrieve elements in the ProofStore in Round 2.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not verify the proof of representation of "
							+ "the Recipient's commitment in Round 2.",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		System.out.println("  Sign - Round 2: Commitment and proof of representation verified.");
		System.out.println("  Sign - Round 2: Pre-Signature and proof of representation sent.");

		try {
			signer.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer failed to close the connection to the Recipient soundly.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Sign: Completed");
	}

	void signbc(ExtendedKeyPair ekp, String nym, String hostAddress, int portNumber) throws IOException, ClassNotFoundException, InterruptedException {
		System.out.println("  Sign: Acts as client for interactive signing of binding credential.");
		System.out.println("hostaddress: " + hostAddress);
		System.out.println("portNumber: " + portNumber);
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);

		BigInteger pseudonym = new BigInteger(nym, 16);
		setupHashToPrime();
		this.e_i = computeHashToPrime(nym);
		pseudonymPrimes.put(nym, this.e_i);

		System.out.println(" prime number: " + this.e_i);

		SignerOrchestratorBC signer = new SignerOrchestratorBC(pseudonym, this.e_i, ekp, messageGateway);

		System.out.print("  Sign: Initializing the Signer role...");
		try {
			signer.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not establish a connection to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Sign - Round 0: Starting round0: Sending nonce...");
		try {
			signer.round0();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not send the nonce to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();
		System.out.print("  Sign - Round 2: Waiting for the Recipient's commitment...");
		try {
			signer.round2();
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not read the GraphML file in Round 2.",
					TopographiaErrorCodes.EX_IOERR);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Signer not store/retrieve elements in the ProofStore in Round 2.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not verify the proof of representation of "
							+ "the Recipient's commitment in Round 2.",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");
		System.out.println("  Sign - Round 2: Commitment and proof of representation verified.");
		System.out.println("  Sign - Round 2: Pre-Signature and proof of representation sent.");


		try {
			signer.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer failed to close the connection to the Recipient soundly.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Sign: Completed\n");
		Thread.sleep(1000);
	}

	void signBindings(ExtendedKeyPair ekp, String graphFilename, Map<String, BigInteger> pseudonymPrimes, String hostAddress, int portNumber) throws IOException, NoSuchAlgorithmException, ProofStoreException, InterruptedException, EncodingException {
		System.out.println("  Sign: Acts as client for interactive signing of graph signature of binding credentials.");
		System.out.println(" Sign: Request proof of possession for each binding credential.");

		List<String> pslist = persistenceUtil.readFileLines(DEF_PSEUDONYMS);
		for (int i = 0; i < pslist.size(); i++) {
			System.out.println("Iteration: " + i);
			System.out.println("hostaddress: " + hostAddress);
			System.out.println("portNumber: " + portNumber);
			verifyvc(hostAddress, portNumber);
			portNumber++;
		}

		System.out.println("Successful proof of possession for binding credentials.");
		System.out.println("Start issuing of graph signature...");


		hostAddress = "127.0.0.1";
		portNumber = 8888;
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);

		System.out.println("Sign: graph file name: " + graphFilename);
		pseudonymPrimes = persistenceUtil.readFileLinesMap(DEF_PSEUDONYMS_PRIMES);

		List<BigInteger> primes = new ArrayList<BigInteger>(pseudonymPrimes.values());
		// add the primes in the interface
		IGraphEncoding encoding = new PseudonymPrimeEncoding(ekp.getGraphEncodingParameters(), primes);
		System.out.println("  Sign: Setup encoding...");
		encoding.setupEncoding();
		SignerOrchestrator signer = new SignerOrchestrator(graphFilename, ekp, encoding, messageGateway);

		System.out.print("  Sign: Initializing the Signer role...");
		try {
			signer.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not establish a connection to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Sign - Round 0: Starting round0: Sending nonce...");
		try {
			signer.round0();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not send the nonce to the Recipient in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();
		System.out.print("  Sign - Round 2: Waiting for the Recipient's commitment...");
		try {
			signer.round2();
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException | ImportException | EncodingException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not read the GraphML file in Round 2.",
					TopographiaErrorCodes.EX_IOERR);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Signer not store/retrieve elements in the ProofStore in Round 2.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Signer could not verify the proof of representation of "
							+ "the Recipient's commitment in Round 2.",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		System.out.println("  Sign - Round 2: Commitment and proof of representation verified.");
		System.out.println("  Sign - Round 2: Pre-Signature and proof of representation sent.");

		try {
			signer.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Signer failed to close the connection to the Recipient soundly.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Sign: Completed");


	}

	void receive(String graphFilename, String sigmaFilename, String hostAddress, int portNumber) {
		System.out.println("  Receive: Acts as host to receive a new graph signature.");
		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);
		RecipientOrchestrator recipient = new RecipientOrchestrator(graphFilename, epk, messageGateway);
		System.out.print("  Receive: Initializing the Recipient role...");
		try {
			recipient.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not open a server socket for the Signer in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Receive - Round 1: Waiting the Signer's nonce...");
		try {
			recipient.round1();
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not complete its commitment in Round 1.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the nonce from the Signer in Round 1.",
					TopographiaErrorCodes.EX_NOHOST);
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]");
		System.out.println();
		System.out.print("  Receive - Round 3: Waiting for the Signer's pre-signature...");
		try {
			recipient.round3();
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not verify the Signer's proof on the "
							+ "presented new signature in Round 3.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not access expected "
							+ "data in the ProofStore in Round 3.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "There was an IO Exception while the TOPOGRAPHIA Recipient "
							+ "sought to receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println("  Receive - Round 3: Received pre-signature from Signer.");
		System.out.println("  Receive - Round 3: Representation proof on pre-signature verified.");
		System.out.println("  Receive - Round 3: Signature completed; internal consistency checked.");

		try {
			recipient.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}

		System.out.println();

		System.out.print("  Receive: Storing the received graph signature: "
				+ sigmaFilename + "...");
		try {
			recipient.serializeFinalSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The graph signature of the Recipient was not "
							+ "correctly assembled; returned null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The Recipient could not write the obtained graph signature to disk.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.println("  Receive: Completed");
	}

	void receivebc(String graphFilename, String sigmaFilename, int i, String hostAddress, int portNumber) throws InterruptedException, IOException {
		System.out.println("  Receive: Acts as host to receive a new binding credential.");
		System.out.println("hostaddress: " + hostAddress);
		System.out.println("portNumber: " + portNumber);
		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);

		RecipientOrchestratorBC recipient = new RecipientOrchestratorBC(epk, messageGateway);

		System.out.print("  Receive: Initializing the Recipient role...");
		try {
			recipient.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not open a server socket for the Signer in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Receive - Round 1: Waiting the Signer's nonce...");
		try {
			recipient.round1();
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not complete its commitment in Round 1.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the nonce from the Signer in Round 1.",
					TopographiaErrorCodes.EX_NOHOST);
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]");

		System.out.println();

		System.out.print("  Receive - Round 3: Waiting for the Signer's pre-signature...");
		try {
			recipient.round3();
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not verify the Signer's proof on the "
							+ "presented new signature in Round 3.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not access expected "
							+ "data in the ProofStore in Round 3.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "There was an IO Exception while the TOPOGRAPHIA Recipient "
							+ "sought to receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println("  Receive - Round 3: Received pre-signature from Signer.");
		System.out.println("  Receive - Round 3: Representation proof on pre-signature verified.");
		System.out.println("  Receive - Round 3: Signature completed; internal consistency checked.");

		try {
			recipient.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}

		System.out.println();

		System.out.print("  Receive: Storing the received vertex credential: "
				+ sigmaFilename + "...");
		try {
			recipient.serializeFinalSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The vertex credential of the Recipient was not "
							+ "correctly assembled; returned null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The Recipient could not write the obtained vertex credential to disk.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.println("  Receive: Completed\n");
		Thread.sleep(1000);
	}

	void receiveBindings(String graphFilename, String sigmaFilename, List<String> pseudonyms, String hostAddress, int portNumber) throws FileNotFoundException, ProofStoreException, NoSuchAlgorithmException, InterruptedException {

		System.out.println("  Receive: Acts as host to receive a new graph signature.");
		hostAddress = "127.0.0.1";
		portNumber = 8888;
		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);
		System.out.println("Receive: graph file name: " + graphFilename);
		RecipientOrchestrator recipient = new RecipientOrchestrator(graphFilename, epk, messageGateway);
		System.out.print("  Receive: Initializing the binding Recipient role...");
		try {
			recipient.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not open a server socket for the Signer in Round 0.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Receive - Round 1: Waiting the Signer's nonce...");
		try {
			recipient.round1();
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not complete its commitment in Round 1.",
					TopographiaErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the nonce from the Signer in Round 1.",
					TopographiaErrorCodes.EX_NOHOST);
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not compute the Fiat-Shamir "
							+ "hash in Round 2 due to missing hash algorithm.",
					TopographiaErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]");
		System.out.println();
		System.out.print("  Receive - Round 3: Waiting for the Signer's pre-signature...");
		try {
			recipient.round3();
		} catch (VerificationException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not verify the Signer's proof on the "
							+ "presented new signature in Round 3.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not access expected "
							+ "data in the ProofStore in Round 3.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "There was an IO Exception while the TOPOGRAPHIA Recipient "
							+ "sought to receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println("  Receive - Round 3: Received pre-signature from Signer.");
		System.out.println("  Receive - Round 3: Representation proof on pre-signature verified.");
		System.out.println("  Receive - Round 3: Signature completed; internal consistency checked.");

		try {
			recipient.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Recipient could not receive the signature from the Signer in Round 3.",
					TopographiaErrorCodes.EX_NOHOST);
		}

		System.out.println();

		System.out.print("  Receive: Storing the received graph signature: "
				+ sigmaFilename + "...");
		try {
			recipient.serializeFinalSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The graph signature of the Recipient was not "
							+ "correctly assembled; returned null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The Recipient could not write the obtained graph signature to disk.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");
		System.out.println("  Receive: Completed");

	}

	void prove(String graphFilename, String sigmaFilename, String hostAddress, Integer portNumber) throws ProofStoreException, NoSuchAlgorithmException {
		System.out.println("  Prove: Acts as host prover for certified graph " + graphFilename + ".");

		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);
		ProverOrchestrator prover = new ProverOrchestrator(epk, messageGateway);

		System.out.print("  Prove: Reading the graph signature from file: "
				+ sigmaFilename + "...");
		try {
			prover.readSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The Prover's graph signature was null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (ClassNotFoundException e) {
			handleException(e, "The signature file did not match the GSSignature class.",
					TopographiaErrorCodes.EX_CRITFILE);
		} catch (IOException e) {
			handleException(e, "The Prover could not read the graph signature from disk.",
					TopographiaErrorCodes.EX_CANTCREAT);
		}
		System.out.println("   [done]");


		System.out.print("  Prove: Initializing the Prover role...");
		try {
			prover.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Prover could not open a socket to receive "
							+ "messages from the Verifier.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Prove: 1. Provers establishing signature proof witnesses...");
		prover.executePreChallengePhase();
		System.out.println("   [done]");

		System.out.print("  Prove: 2. Prover Orchestrator computing overall challenge...");
		BigInteger cChallenge = prover.computeChallenge();
		System.out.println("   [done]");

		System.out.print("  Prove: 3. Provers computing signature proof responses...");
		try {
			prover.executePostChallengePhase(cChallenge);
		} catch (IOException e) {
			handleException(e, "The Prover not send the proof to the Verifier.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");
		System.out.println("  Prove: Signature proof of knowledge sent to Verifier.");

		System.out.println("  Prove: Completed");
	}

	void provevc(String graphFilename, String bCredFilename, String hostAddress, Integer portNumber) throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {
		System.out.println("  Prove: Acts as host prover for binding credential.");
		System.out.println("hostAddress: " + hostAddress);
		System.out.println("portNumber: " + portNumber);

		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);

		ProverOrchestratorBC prover = new ProverOrchestratorBC(epk, messageGateway);
		System.out.print("  Prove: Reading the binding credential from file: "
				+ bCredFilename + "...");
		try {
			prover.readSignature(bCredFilename);
		} catch (NullPointerException e) {
			handleException(e, "The Prover's binding credential was null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (ClassNotFoundException e) {
			handleException(e, "The signature file did not match the GSSignature class.",
					TopographiaErrorCodes.EX_CRITFILE);
		} catch (IOException e) {
			handleException(e, "The Prover could not read the binding credential from disk.",
					TopographiaErrorCodes.EX_CANTCREAT);
		}
		System.out.println("   [done]");

		System.out.print("  Prove: Initializing the Prover role...");
		try {
			prover.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Prover could not open a socket to receive "
							+ "messages from the Verifier.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Prove: 1. Provers establishing signature proof witnesses...");
		prover.executePreChallengePhase();
		System.out.println("   [done]");

		System.out.print("  Prove: 2. Prover Orchestrator computing overall challenge...");
		BigInteger cChallenge = prover.computeChallenge();
		System.out.println("   [done]");

		System.out.print("  Prove: 3. Provers computing signature proof responses...");
		try {
			prover.executePostChallengePhase(cChallenge);
		} catch (IOException e) {
			handleException(e, "The Prover could not send the proof to the Verifier.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");
		System.out.println("  Prove: Signature proof of knowledge sent to Verifier.");

		System.out.println("  Prove: Completed");
		try {
			prover.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Prover failed to close the connection to the Verifier soundly.",
					TopographiaErrorCodes.EX_IOERR);
		}

	}

	void proveBindings(String graphFilename, String sigmaFilename, String hostAddress, Integer portNumber) throws IOException, NoSuchAlgorithmException, ProofStoreException, InterruptedException, EncodingException {
		int port = portNumber;
		System.out.println("  Prove: Acts as prover for proof of binding");
		System.out.println(" Prove: Request proof of possession for each binding credential.");

		List<String> pslist = persistenceUtil.readFileLines(DEF_PSEUDONYMS);
		for (int i = 0; i < pslist.size(); i++) {
			System.out.println("Iteration: " + i);
			System.out.println("hostaddress: " + hostAddress);
			System.out.println("portNumber: " + portNumber);
			verifyvc(hostAddress, portNumber);
			portNumber++;
		}

		System.out.println("Successful proof of possession for binding credentials.");
		System.out.println("Start proof of possession of graph signature...");
//			System.out.println("hostAddress: " + hostAddress);
//			System.out.println("portNumber: " + port);


		System.out.println("  Prove: Acts as host prover for certified graph " + graphFilename + ".");
		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, port);
		ProverOrchestratorPoB prover = new ProverOrchestratorPoB(epk, messageGateway);

		System.out.print("  Prove: Reading the graph signature from file: "
				+ sigmaFilename + "...");
		try {
			prover.readSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The Prover's graph signature was null.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (ClassNotFoundException e) {
			handleException(e, "The signature file did not match the GSSignature class.",
					TopographiaErrorCodes.EX_CRITFILE);
		} catch (IOException e) {
			handleException(e, "The Prover could not read the graph signature from disk.",
					TopographiaErrorCodes.EX_CANTCREAT);
		}
		System.out.println("   [done]");


		System.out.print("  Prove: Initializing the Prover role...");
		try {
			prover.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Prover could not open a socket to receive "
							+ "messages from the Verifier.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Prove: 1. Provers establishing signature proof witnesses...");
		prover.executePreChallengePhase();
		System.out.println("   [done]");

		System.out.print("  Prove: 2. Prover Orchestrator computing overall challenge...");
		BigInteger cChallenge = prover.computeChallenge();
		System.out.println("   [done]");

		System.out.print("  Prove: 3. Provers computing signature proof responses...");
		try {
			prover.executePostChallengePhase(cChallenge);
		} catch (IOException e) {
			handleException(e, "The Prover not send the proof to the Verifier.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");
		System.out.println("  Prove: Signature proof of knowledge sent to Verifier.");

		System.out.println("  Prove: Completed");
	}

	void verify(Vector<Integer> vertexQueries, String hostAddress, Integer portNumber) throws NoSuchAlgorithmException, ProofStoreException {
		System.out.println("  Verify: Acts as client for geo-location verification.");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		VerifierOrchestrator verifier = new VerifierOrchestrator(epk, messageGateway);
		System.out.print("  Verify: Creating geo-location query predicate...");
		verifier.createQuery(vertexQueries);
		System.out.println("   [done]");

		System.out.print("  Verify: Initializing the Verifier role...");
		try {
			verifier.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier could not open a connection to the Prover.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.println("  Verify: 1. Sent Prover to prover, awaiting signature proof...");
		try {
			verifier.receiveProverMessage();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. "
							+ "Illegal message lengths.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofException e) {
			handleException(e, "The TOPOGRAPHIA Prover reported that it cannot complete the proof.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: 2. Computing verification for geo-location verification...");
		try {
			verifier.executeVerification();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}

		verifier.computeChallenge();

		try {
			verifier.verifyChallenge();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: Signature proof ACCEPTED: Geo-location separation fulfilled for ");
		System.out.print("[ ");
		for (Iterator<Integer> iterator = vertexQueries.iterator(); iterator.hasNext(); ) {
			Integer queriedVertex = (Integer) iterator.next();
			System.out.print(queriedVertex);
			if (iterator.hasNext()) System.out.print(", ");
		}
		System.out.println(" ].");


		try {
			verifier.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Verify: Completed");
	}

	void verifyvc(String hostAddress, Integer portNumber) throws NoSuchAlgorithmException, ProofStoreException, InterruptedException {
		System.out.println("  Verify: Acts as client for vertex credential verification.");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		VerifierOrchestratorBC verifier = new VerifierOrchestratorBC(epk, messageGateway);

		System.out.println("  Verify: Initializing the Verifier role...");
		try {
			verifier.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier could not open a connection to the Prover.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.println("  Verify: 1. Sent Prover to prover, awaiting signature proof...");
		try {
			verifier.receiveProverMessage();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. "
							+ "Illegal message lengths.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofException e) {
			handleException(e, "The TOPOGRAPHIA Prover reported that it cannot complete the proof.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: 2. Computing verification for vertex credential...");
		try {
			verifier.executeVerification();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}

		verifier.computeChallenge();

		try {
			verifier.verifyChallenge();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: Signature proof ACCEPTED ");
		System.out.print("[ ");

		try {
			verifier.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Verify: Completed");
//		Thread.sleep(1000);

	}

	void verifyBindings(String hostAddress, int portNumber) {
		System.out.println("  Verify: Acts as client for verification of graph signature bound to hardware.");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		VerifierOrchestratorPoB verifier = new VerifierOrchestratorPoB(epk, messageGateway);

		System.out.print("  Verify: Initializing the Verifier role...");
		try {
			verifier.init();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier could not open a connection to the Prover.",
					TopographiaErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.println("  Verify: 1. Sent Prover to prover, awaiting signature proof...");
		try {
			verifier.receiveProverMessage();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. "
							+ "Illegal message lengths.",
					TopographiaErrorCodes.EX_VERIFY);
		} catch (ProofException e) {
			handleException(e, "The TOPOGRAPHIA Prover reported that it cannot complete the proof.",
					TopographiaErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: 2. Computing verification for proof of binding...");
		try {
			verifier.executeVerification();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}

		verifier.computeChallenge();

		try {
			verifier.verifyChallenge();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOGRAPHIA Prover could not be verified. ",
					TopographiaErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		try {
			verifier.close();
		} catch (IOException e) {
			handleException(e, "The TOPOGRAPHIA Verifier not receive the proof from the Prover.",
					TopographiaErrorCodes.EX_IOERR);
		}

		System.out.println("  Verify: Completed");
	}

	private static void handleException(Throwable e, String highLevelMsg, int exitCode) {
		System.err.println("\n\nTOPOGRAPHIA Exception:\n" + highLevelMsg);
		if (e.getMessage() != null) System.err.println("\nException message: " + e.getMessage() + "\n");

		if (Topographia.verbose) {
			System.err.println("\nCause of the Exception:\n" + e);

			System.err.println("\nPrinting the stack trace:");
			e.printStackTrace();
		}
		System.err.println("\nTOPOGRAPHIA aborting.");

		System.exit(exitCode);
	}


	public KeyGenParameters getKeyGenParams() {
		return this.keyGenParams;
	}
}
