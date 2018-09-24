package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.integration.MockGatewayProxy;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.ProofRequest;
import eu.prismacloud.primitives.zkpgs.message.ProofType;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProverOrchestratorTest {
	private SignerKeyPair gsk;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private GSSigningOracle oracle;
	private ProofStore<Object> proofStore;
	private BigInteger randomM;
	private GSSignature testSigma;
	private BigInteger n_2;
	private ProverOrchestrator prover;
	private static final String SIGNER_INFRA_GS_SER = "signer-infra.gs.ser";
	private VerifierOrchestrator verifier;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 8888;
	private static final String SERVER = "SERVER";
	private MockGatewayProxy mockGateway;
	private FilePersistenceUtil persistenceUtil;
	private String extendedKeyPairFileName;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		JSONParameters parameters = new JSONParameters();
		keyGenParameters = parameters.getKeyGenParameters();
		graphEncodingParameters = parameters.getGraphEncodingParameters();
		persistenceUtil = new FilePersistenceUtil();
		extendedKeyPairFileName = "ExtendedKeyPair-" + keyGenParameters.getL_n() + ".ser";
		extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
	}

	@BeforeEach
	void setUp() throws ProofStoreException, IOException {
		proofStore = new ProofStore<Object>();
		// create a mock gateway for testing prover orchestrator
		mockGateway = new MockGatewayProxy(SERVER, HOST, PORT);
		prover = new ProverOrchestrator(extendedKeyPair.getExtendedPublicKey(), mockGateway);
	}

	@Test
	@DisplayName("Test creating prover orchestrator")
	void proverOrchestrator() throws IOException, ClassNotFoundException {
		ProverOrchestrator prover = new ProverOrchestrator(extendedKeyPair.getExtendedPublicKey(), mockGateway);
		assertNotNull(prover);
	}

	void createProofReqMsg() throws IOException {
		Vector<Integer> vertexQuery = new Vector<Integer>();
		vertexQuery.add(1);
		vertexQuery.add(11);
		ProofRequest proofRequest = new ProofRequest(ProofType.GEOLOCATION_SEPARATION, vertexQuery);
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("proof.request"), proofRequest);
		mockGateway.send(new GSMessage(messageElements));
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
	@DisplayName("Test initializing prover orchestrator receiving a proof request and nonce")
	void init() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createProofReqMsg();
		createNonceMsg();
		prover.init();
	}

	@Test
	@DisplayName("Test initializing prover orchestrator with illegal proof request ")
	void initIllegalProofReq() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createIllegalProofReqMsg();
		createNonceMsg();
		assertThrows(ProofException.class, () -> {
			prover.init();
		});
	}

	@Test
	@DisplayName("Test initializing prover orchestrator with no vertices in proof request ")
	void initNoVerticesProofReq() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createNoVerticesProofReqMsg();
		createNonceMsg();
		assertThrows(ProofException.class, () -> {
			prover.init();
		});
	}

	@Test
	@DisplayName("Test executing pre-challenge phase for prover orchestrator")
	void executePreChallengePhase() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
	}

	@Test
	@DisplayName("Test creating  proof signature for prover orchestrator")
	void createProofSignature() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		gslog.info("cChallenge: " + cChallenge);
		assertNotNull(cChallenge);
		prover.executePostChallengePhase(cChallenge);
		ProofSignature proofSignature = prover.createProofSignature();
		assertNotNull(proofSignature);
		int elemSize = proofSignature.getProofSignatureElements().size();
		gslog.info("proof signature elements size: " + elemSize);
		assertTrue(elemSize > 0);
	}

	@Test
	@DisplayName("Test computing challenge for prover orchestrator")
	void computeChallenge() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		gslog.info("cChallenge: " + cChallenge);
		assertNotNull(cChallenge);
	}

	@Test
	@DisplayName("Test executing post challenge phase for prover orchestrator")
	void executePostChallengePhase() throws IOException, ClassNotFoundException {
		prover.readSignature(SIGNER_INFRA_GS_SER);
		createProofReqMsg();
		createNonceMsg();
		prover.init();
		prover.executePreChallengePhase();
		BigInteger cChallenge = prover.computeChallenge();
		gslog.info("cChallenge: " + cChallenge);
		assertNotNull(cChallenge);
		prover.executePostChallengePhase(cChallenge);
	}
}
