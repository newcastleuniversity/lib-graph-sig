package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.integration.MockGatewayProxy;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
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
		signerOrchestrator.round0();
	}

	@BeforeEach
	void setUp() {
	}

	@Test
	void round1() throws ProofStoreException {
		// recipientOrchestrator.round1();
		fail("Test not implemented yet.");
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
		//  signerOrchestrator.round2();
		//  recipientOrchestrator.round3();
		fail("Test not implemented yet.");
	}
}
