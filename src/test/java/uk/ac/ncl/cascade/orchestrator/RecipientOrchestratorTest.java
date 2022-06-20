package uk.ac.ncl.cascade.orchestrator;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.integration.MockGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPrivateKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.fail;

@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
@TestInstance(Lifecycle.PER_CLASS)
class RecipientOrchestratorTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private SignerKeyPair gsk;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proofStore;
	private ProofSignature proofSignature;
	private SignerOrchestrator signerOrchestrator;
	private RecipientOrchestrator recipientOrchestrator;
	private GroupElement baseR0;
	private SignerPublicKey publicKey;
	private SignerPrivateKey privateKey;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 9999;
	private static final String SERVER = "SERVER";

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		gsk = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		IMessageGateway messageGateway = new MockGatewayProxy(SERVER, HOST, PORT);
		signerOrchestrator = new SignerOrchestrator(extendedKeyPair, messageGateway);
		recipientOrchestrator =
				new RecipientOrchestrator(
						extendedKeyPair.getExtendedPublicKey(), messageGateway);
		signerOrchestrator.round0();
//		signerOrchestrator.round0();
	}

	@BeforeEach
	void setUp() {
	}

	@Test
	void round1() throws ProofStoreException, IOException, NoSuchAlgorithmException {
		 recipientOrchestrator.round1();
//		fail("Test not implemented yet.");
	}

	@Test
	void computeChallenge() {
		fail("Test not implemented yet.");
	}

	@Test
	void createProofSignature() {
		fail("Test not implemented yet.");
	}

	@Test
	void round3() throws Exception {
		  signerOrchestrator.round2();
		  recipientOrchestrator.round3();
//		fail("Test not implemented yet.");
	}
}
