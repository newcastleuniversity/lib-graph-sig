package uk.ac.ncl.cascade.orchestrator;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
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
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.util.logging.Logger;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/** */
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
@TestInstance(Lifecycle.PER_CLASS)
class SignerOrchestratorTest {
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
	private String bitLength = "2048";
	private SignerPublicKey publicKey;
	private SignerPrivateKey privateKey;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 9999;
	private FilePersistenceUtil persistenceUtil;
	private IMessageGateway messageGateway;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		persistenceUtil = new FilePersistenceUtil();
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
		messageGateway = new MockGatewayProxy(DefaultValues.CLIENT, HOST, PORT);
	}

	@Test
	void testCreateSignerOrchestrator() {
		signerOrchestrator = new SignerOrchestrator(extendedKeyPair, messageGateway);
		assertNotNull(signerOrchestrator);
	}

	@Test
	void round0() throws Exception {
		signerOrchestrator = new SignerOrchestrator(extendedKeyPair, messageGateway);
		signerOrchestrator.init();
		recipientOrchestrator = new RecipientOrchestrator(extendedKeyPair.getExtendedPublicKey(), messageGateway);
		recipientOrchestrator.init();
		signerOrchestrator.round0();
		recipientOrchestrator.round1();
		signerOrchestrator.round2();
		recipientOrchestrator.round3();
		recipientOrchestrator.close();
		signerOrchestrator.close();

//		GSSignature gsSignature = recipientOrchestrator.getGraphSignature();
//		persistenceUtil.write(gsSignature,"graphSignature.ser");
//		assertNotNull(gsSignature);
	}

	@Test
	void round2() throws Exception {
//    signerOrchestrator.round2();
		fail("Test not implemented yet.");
	}

	@Test
	void computeChallenge() {
		fail("Test not implemented yet.");
	}

	@Test
	void verifyChallenge() {
		fail("Test not implemented yet.");
	}

	@Test
	void createPartialSignature() {
		fail("Test not implemented yet.");
	}

	@Test
	void computeRandomness() {
		fail("Test not implemented yet.");
	}

	@Test
	void computevPrimePrime() {
		fail("Test not implemented yet.");
	}

	@Test
	void store() {
		fail("Test not implemented yet.");
	}
}
