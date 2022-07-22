package uk.ac.ncl.cascade.binding;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.integration.MockGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static uk.ac.ncl.cascade.zkpgs.DefaultValues.*;


/**
 * Test the orchestration of the proof of binding with multiple binding credentials
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.BINDING)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ShowingProtocolPoBTest {
	List<String> fileNames = new ArrayList<String>();
	private final static String HOST = "127.0.0.1";
	private final static int PORT = 7777;
	private static final int bindingCredentialsNo = 50;
	private final Logger gslog = GSLoggerConfiguration.getGSlog();
	private ExtendedKeyPair extendedKeyPair;
	private MockGatewayProxy mockGateway;
	private List<ProverOrchestratorBC> bcProvers;
	private List<VerifierOrchestratorBC> bcVerifiers;
	private MessageGatewayProxy messageGateway;
	private MockGatewayProxy mockGatewayBC;

	@BeforeEach
	void setUp() throws IOException, ClassNotFoundException {

		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		KeyGenParameters keyGenParameters = baseTest.getKeyGenParameters();
		gslog.info("read ExtendedKeyPair..");
		String extendedKeyPairFileName = "ExtendedKeyPair-binding-" + keyGenParameters.getL_n() + ".ser";
		extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		PseudonymPrimeEncoding ps = (PseudonymPrimeEncoding) extendedKeyPair.getGraphEncoding();
		// dependency for pseudonym prime encoding for the binding credential
		assertTrue(ps instanceof PseudonymPrimeEncoding);

	}

	@Test
	@Order(1)
	void readBindingCredentials() throws IOException, ClassNotFoundException {

		ProverOrchestratorBC bcProver;
		for (int i = 0; i < bindingCredentialsNo; i++) {
			fileNames.add("vertexCred_" + i + ".ser");
			bcProver = new ProverOrchestratorBC(this.extendedKeyPair.getExtendedPublicKey(), mockGateway);
			bcProver.readSignature("vertexCred_" + i + ".ser");
			assertNotNull(bcProver);
		}

	}

	@Test
	@Order(2)
	void executePreChallengePhase() throws IOException, ClassNotFoundException, ProofStoreException, VerificationException, NoSuchAlgorithmException {
		for (int i = 0; i < bindingCredentialsNo; i++) {
			fileNames.add("vertexCred_" + i + ".ser");
		}

		ProverOrchestratorBC bcProver;
		VerifierOrchestratorBC bcVerifier;
		bcVerifiers = new ArrayList<VerifierOrchestratorBC>();

		System.out.println("Thread: " + Thread.currentThread().getName());
		for (int i = 0; i < bindingCredentialsNo; i++) {
			gslog.info("iteration: " + i);
			mockGateway = new MockGatewayProxy(SERVER, HOST, PORT);
			bcProver = new ProverOrchestratorBC(this.extendedKeyPair.getExtendedPublicKey(), mockGateway);
			assertNotNull(bcProver);
			bcVerifier = new VerifierOrchestratorBC(this.extendedKeyPair.getExtendedPublicKey(), mockGateway);
			assertNotNull(bcVerifier);
			bcVerifiers.add(i, bcVerifier);

			bcProver.readSignature("vertexCred_" + i + ".ser");
			bcVerifier.init();
			bcProver.init();

			bcProver.executePreChallengePhase();
			BigInteger cChallenge = bcProver.computeChallenge();
			assertNotNull(cChallenge);
			bcProver.executePostChallengePhase(cChallenge);
			bcVerifier.receiveProverMessage();

			bcVerifier.executeVerification();
			bcVerifier.computeChallenge();
			bcVerifier.verifyChallenge();
//			bcProver.close();
//			bcVerifier.close();


		}


	}

	@Execution(ExecutionMode.CONCURRENT)
	@Test
	@Order(3)
	void testMultiProverBCOrchestrator() throws IOException, ProofStoreException, NoSuchAlgorithmException, ClassNotFoundException, VerificationException {
		gslog.info("multi prover bc orchestrator");
		ProverOrchestratorMultiBC multiprover = new ProverOrchestratorMultiBC(this.extendedKeyPair.getExtendedPublicKey(), bindingCredentialsNo);
		assertNotNull(multiprover);

		List<IMessageGateway> messageGateways = new ArrayList<IMessageGateway>();

		for (int i = 0; i < bindingCredentialsNo; i++) {
			messageGateway = new MessageGatewayProxy(SERVER, HOST, PORT + i);
			messageGateways.add(i, messageGateway);
		}
		multiprover.executeProvers(messageGateways);
	}

	@Execution(ExecutionMode.CONCURRENT)
	@Test
	@Order(4)
	void testMultiVerifierBCOrchestrator() throws IOException, ProofStoreException, NoSuchAlgorithmException, ClassNotFoundException, VerificationException {
		VerifierOrchestratorMultiBC multiverifier = new VerifierOrchestratorMultiBC(this.extendedKeyPair.getExtendedPublicKey(), bindingCredentialsNo);
		List<IMessageGateway> messageGateways = new ArrayList<IMessageGateway>();

		gslog.info("multi verifier bc orchestrator");
		for (int i = 0; i < bindingCredentialsNo; i++) {
			messageGateway = new MessageGatewayProxy(CLIENT, HOST, PORT + i);
			messageGateways.add(i, messageGateway);
		}
		multiverifier.executeVerifiers(messageGateways);

	}


}