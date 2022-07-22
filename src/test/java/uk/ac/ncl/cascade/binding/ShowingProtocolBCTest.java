package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.integration.MockGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ShowingProtocolBCTest {
	private SignerKeyPair gsk;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private GSSigningOracle oracle;
	private ProofStore<Object> proofStore;
	private BigInteger randomM;
	private GSSignature testSigma;
	private BigInteger n_2;
	private ProverOrchestratorBC prover;
	private static final String VC_SIGNATURE_SER = "vertexCred_0.ser";
	private VerifierOrchestratorBC verifier;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 8888;
	private static final String SERVER = "SERVER";
	private MockGatewayProxy mockGateway;
	private FilePersistenceUtil persistenceUtil;
	private String extendedKeyPairFileName;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		persistenceUtil = new FilePersistenceUtil();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		gslog.info("read ExtendedKeyPair..");
		String extendedKeyPairFileName = "ExtendedKeyPair-binding-" + keyGenParameters.getL_n() + ".ser";
		extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		PseudonymPrimeEncoding ps = (PseudonymPrimeEncoding) extendedKeyPair.getGraphEncoding();
		// dependency for pseudonym prime encoding for the binding credential
		assertTrue(ps instanceof PseudonymPrimeEncoding);
		proofStore = new ProofStore<Object>();
		// create a mock gateway for testing prover orchestrator for vertex credential
		mockGateway = new MockGatewayProxy(SERVER, HOST, PORT);
		prover = new ProverOrchestratorBC(extendedKeyPair.getExtendedPublicKey(), mockGateway);
		verifier = new VerifierOrchestratorBC(extendedKeyPair.getExtendedPublicKey(), mockGateway);
	}

	@Test
	@DisplayName("Test creating prover orchestrator for binding credential")
	void proverOrchestrator() throws IOException, ClassNotFoundException {
		ProverOrchestratorBC prover = new ProverOrchestratorBC(extendedKeyPair.getExtendedPublicKey(), mockGateway);
		assertNotNull(prover);
	}

	@Test
	@DisplayName("Test showing protocol for binding credential")
	void testShowingProtocolBC() throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException, VerificationException {
		prover.readSignature(VC_SIGNATURE_SER);
		verifier.init();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		assertNotNull(cChallenge);
		gslog.info("cChallenge: " + cChallenge);
		prover.executePostChallengePhase(cChallenge);

		verifier.receiveProverMessage();
		verifier.executeVerification();
		verifier.computeChallenge();
		verifier.verifyChallenge();
	}
}