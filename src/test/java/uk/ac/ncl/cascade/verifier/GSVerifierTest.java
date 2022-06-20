package uk.ac.ncl.cascade.verifier;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import uk.ac.ncl.cascade.zkpgs.verifier.GSVerifier;

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
