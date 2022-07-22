package uk.ac.ncl.cascade.binding;

import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.hashToPrime.HashToPrimeElimination;
import uk.ac.ncl.cascade.hashToPrime.NaorReingoldPRG;
import uk.ac.ncl.cascade.hashToPrime.SquareHashing;
import uk.ac.ncl.cascade.integration.MockGatewayProxy;
import uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues;
import uk.ac.ncl.cascade.zkpgs.encoding.IGraphEncoding;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues.*;
import static uk.ac.ncl.cascade.zkpgs.DefaultValues.*;

/**
 * Test the issuing protocol of the graph signature encoding vertex primes for the proof of binding corresponding to a graph with 50 vertices
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuingProtocolPoBTest {
	private FilePersistenceUtil persistenceUtil;
	private final static String HOST = "127.0.0.1";
	private final static String graphFilename = "signer-infra-50.graphml";
	private final Logger gslog = GSLoggerConfiguration.getGSlog();
	private SignerOrchestrator signer;
	private RecipientOrchestrator recipient;
	private PrimeOrderGroup group;
	private KeyGenParameters hKeyGenParameters;

	@BeforeEach
	void setUp() throws IOException, ClassNotFoundException, EncodingException, ProofStoreException, NoSuchAlgorithmException, VerificationException {

		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		persistenceUtil = new FilePersistenceUtil();
		KeyGenParameters keyGenParameters = baseTest.getKeyGenParameters();
		gslog.info("read ExtendedKeyPair..");
		String extendedKeyPairFileName = "ExtendedKeyPair-binding-" + keyGenParameters.getL_n() + ".ser";
		ExtendedKeyPair extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		PseudonymPrimeEncoding ps = (PseudonymPrimeEncoding) extendedKeyPair.getGraphEncoding();
		assertTrue(ps instanceof PseudonymPrimeEncoding);

		MockGatewayProxy messageGateway = new MockGatewayProxy(SERVER, HOST, PORT);
		Map<String, BigInteger> pseudonymPrimes = new HashMap<String, BigInteger>();

		List<String> pseudonyms = persistenceUtil.readFileLines(DEF_PSEUDONYMS);

		String bindingCredentialName = "";
		String nym = "";
		boolean isFile;
		File f;

		for (int i = 0; i < pseudonyms.size(); i++) {
			bindingCredentialName = "vertexCred" + "_" + String.valueOf(i) + ".ser";
			// check if binding credential exists
			f = new File(bindingCredentialName);
			isFile = f.exists();
			assertTrue(isFile);
			
			messageGateway = new MockGatewayProxy(SERVER, HOST, PORT + i);
			nym = pseudonyms.get(i);
			BigInteger pseudonym = new BigInteger(nym, 16);
			setupHashToPrime();
			BigInteger e_i = computeHashToPrime(nym);
			pseudonymPrimes.put(nym, e_i);

			System.out.println(" prime number: " + e_i);

			SignerOrchestratorBC signerOrchestratorBC = new SignerOrchestratorBC(pseudonym, e_i, extendedKeyPair, messageGateway);
			assertNotNull(signerOrchestratorBC);

			RecipientOrchestratorBC recipientOrchestratorBC = new RecipientOrchestratorBC(extendedKeyPair.getExtendedPublicKey(), messageGateway);
			assertNotNull(recipientOrchestratorBC);

			signerOrchestratorBC.init();
			recipientOrchestratorBC.init();
			signerOrchestratorBC.round0();
			recipientOrchestratorBC.round1();
			signerOrchestratorBC.round2();
			recipientOrchestratorBC.round3();

			GSSignature gsSignature = recipientOrchestratorBC.getSignature();
			assertNotNull(gsSignature);
			persistenceUtil.write(gsSignature, bindingCredentialName);
			assertNotNull(gsSignature);
		}

		List<BigInteger> primes = new ArrayList<BigInteger>(pseudonymPrimes.values());
		// add the primes in the interface
		IGraphEncoding encoding = new PseudonymPrimeEncoding(extendedKeyPair.getGraphEncodingParameters(), primes);
		System.out.println("  Sign: Setup encoding...");
		encoding.setupEncoding();

		signer = new SignerOrchestrator(graphFilename, extendedKeyPair, encoding, messageGateway);
		assertNotNull(signer);
		recipient = new RecipientOrchestrator(extendedKeyPair.getExtendedPublicKey(), messageGateway);
		assertNotNull(recipient);
	}

	private void setupHashToPrime() throws IOException, ClassNotFoundException {
		int MODULUS_LENGTH = 220;
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

	@Test
	void testProofOfPossessionBindingCredentials() {

	}

	@Test
	void testIssuingProtocolPoB() throws IOException, ProofStoreException, NoSuchAlgorithmException, ImportException, EncodingException, VerificationException {
		signer.init();
		recipient.init();
		signer.round0();
		recipient.round1();
		signer.round2();
		recipient.round3();
		recipient.serializeFinalSignature(DEF_GSSIGNATURE);
	}

}