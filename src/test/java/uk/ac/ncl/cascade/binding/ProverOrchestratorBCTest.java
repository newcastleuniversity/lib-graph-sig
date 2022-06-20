package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.integration.MockGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.ProofRequest;
import uk.ac.ncl.cascade.zkpgs.message.ProofType;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledOnSuite(name = GSSuite.BINDING)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProverOrchestratorBCTest {
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
	private static final String VC_SIGNATURE_SER = "vcSignature.ser";
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
		String extendedKeyPairFileName = "ExtendedKeyPair-" + keyGenParameters.getL_n() + ".ser";
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
	@DisplayName("Test creating prover orchestrator for vertex credential")
	void proverOrchestrator() throws IOException, ClassNotFoundException {
		ProverOrchestratorBC prover = new ProverOrchestratorBC(extendedKeyPair.getExtendedPublicKey(), mockGateway);
		assertNotNull(prover);
	}

	void createIllegalProofReqMsg() throws IOException {
		ProofRequest proofRequest = new ProofRequest(ProofType.NONE, null);
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("proof.request"), proofRequest);
		mockGateway.send(new GSMessage(messageElements));
	}

	void createNoVerticesProofReqMsg() throws IOException {
		ProofRequest proofRequest = new ProofRequest(ProofType.GEOLOCATION_SEPARATION, null);
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("proof.request"), proofRequest);
		mockGateway.send(new GSMessage(messageElements));
	}

	void createNonceMsg() throws IOException {
		BigInteger n_3 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createZkpgsURN("verifier.n_3"), n_3);
		mockGateway.send(new GSMessage(messageElements));
	}

	@Test
	@DisplayName("Test initializing prover orchestrator receiving a nonce")
	void init() throws IOException, ClassNotFoundException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createProofReqMsg();
		createNonceMsg();
		prover.init();
	}

	@Test
	@DisplayName("Test initializing prover orchestrator with illegal proof request ")
	void initIllegalProofReq() throws IOException, ClassNotFoundException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createIllegalProofReqMsg();
		createNonceMsg();
		assertThrows(ProofException.class, () -> {
			prover.init();
		});
	}

	@Test
	@DisplayName("Test initializing prover orchestrator with no vertices in proof request ")
	void initNoVerticesProofReq() throws IOException, ClassNotFoundException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createNoVerticesProofReqMsg();
		createNonceMsg();
		assertThrows(ProofException.class, () -> {
			prover.init();
		});
	}

	@Test
	@DisplayName("Test executing pre-challenge phase for prover orchestrator")
	void executePreChallengePhase() throws IOException, ClassNotFoundException, ProofStoreException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
	}

	@Test
	@DisplayName("Test creating  proof signature for prover orchestrator")
	void createProofSignature() throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException, VerificationException {


		prover.readSignature(VC_SIGNATURE_SER);
//		createProofReqMsg();
//		createNonceMsg();

		verifier.init();
		prover.init();
		prover.executePreChallengePhase();

		BigInteger cChallenge = prover.computeChallenge();

		gslog.info("cChallenge: " + cChallenge);
		Assertions.assertNotNull(cChallenge);
		prover.executePostChallengePhase(cChallenge);
		verifier.receiveProverMessage();

//		assertNotNull(proofSignature);
		verifier.executeVerification();
		verifier.computeChallenge();
		verifier.verifyChallenge();
//		int elemSize = proofSignature.getProofSignatureElements().size();
//		gslog.info("proof signature elements size: " + elemSize);
//		assertTrue(elemSize > 0);
	}

	@Test
	@DisplayName("Test computing challenge for prover orchestrator")
	void computeChallenge() throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		gslog.info("cChallenge: " + cChallenge);
		assertNotNull(cChallenge);
	}

	@Test
	@DisplayName("Test executing post challenge phase for prover orchestrator")
	void executePostChallengePhase() throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException {
		prover.readSignature(VC_SIGNATURE_SER);
//		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		gslog.info("cChallenge: " + cChallenge);
		assertNotNull(cChallenge);
		prover.executePostChallengePhase(cChallenge);
	}
}