package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.integration.MockGatewayProxy;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
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
	private IMessageGateway messageGateway;

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
//    signerOrchestrator.round0();

		//    recipientOrchestrator.round1();
		//
		//    signerOrchestrator.round2();
		//
		//    recipientOrchestrator.round3();

		//    recipientOrchestrator.round3();
		fail("Test not implemented yet.");

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
