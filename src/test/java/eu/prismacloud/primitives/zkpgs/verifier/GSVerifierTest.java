package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;

import static org.junit.Assert.fail;

/** */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
class GSVerifierTest {

	private SignerKeyPair signerKeyPair;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proofStore;
	private GSVerifier verifier;
	private ExtendedPublicKey extendedPublicKey;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
		extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
		proofStore = new ProofStore<Object>();
		IMessageGateway messageGateway = new MessageGatewayProxy("SERVER", "127.0.0.1", 9999);
		verifier = new GSVerifier(extendedPublicKey, messageGateway);
		verifier.init();
	}

	@Test
	void testGSVerifier() {
		fail("Test not implemented yet.");
	}

	@AfterAll
	void tearDown() throws IOException {
		verifier.close();
	}
}
