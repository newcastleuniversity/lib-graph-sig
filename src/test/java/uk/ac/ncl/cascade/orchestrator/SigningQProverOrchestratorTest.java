package uk.ac.ncl.cascade.orchestrator;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SigningQProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.prover.SigningQCorrectnessProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

@TestInstance(Lifecycle.PER_CLASS)
class SigningQProverOrchestratorTest {

	private SignerKeyPair gsk;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private GSSigningOracle oracle;
	private BigInteger randomM;
	private GSSignature testSigma;
	private BigInteger n_2;
	private ProofStore<Object> proofStore;
	private SigningQProverOrchestrator prover;

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
		
		oracle = new GSSigningOracle(extendedKeyPair.getBaseKeyPair(), keyGenParameters);
	}

	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		
		randomM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());

		testSigma = this.oracle.sign(randomM);
		
		n_2 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		
		proofStore.store("issuing.signer.Q", oracle.computeQforSignature(testSigma));
		proofStore.store("issuing.signer.d", oracle.computeDforSignature(testSigma));
		
		prover = new SigningQProverOrchestrator(testSigma, n_2, extendedKeyPair, proofStore);
		prover.init();
	}

	@Test
	void testExecutePreChallengePhase() throws ProofStoreException {
		prover.executePreChallengePhase();
		GroupElement tildeA = (GroupElement)proofStore.retrieve(URNType.buildURNComponent(URNType.TILDEA, SigningQCorrectnessProver.class));
		BigInteger tilded = (BigInteger) proofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		GroupElement Q = (GroupElement) proofStore.retrieve("issuing.signer.Q");
		
		assertEquals(Q.modPow(tilded), tildeA);
	}

	@Test
	void testExecutePostChallengePhase() throws ProofStoreException, NoSuchAlgorithmException {
		prover.executePreChallengePhase();
		BigInteger tilded = (BigInteger) proofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		
		
		BigInteger cPrime = prover.computeChallenge();
		
		prover.executePostChallengePhase(cPrime);
		ProofSignature P_2 = prover.createProofSignature();
		assertNotNull(P_2, "The proof signature P_2 was found null.");
		assertNotNull(P_2.getProofSignatureElements(), "There were no elements in P_2.");
		
		BigInteger outputHatd = (BigInteger) P_2.getProofSignatureElements().get(URN.createZkpgsURN("P_2.hatd"));
		BigInteger outputCPrime = (BigInteger) P_2.getProofSignatureElements().get(URN.createZkpgsURN("P_2.cPrime"));
		
		assertNotNull(outputHatd, "The proof signature output hatd was null.");
		assertNotNull(outputCPrime, "The proof signature output cPrime was null.");
		
		assertEquals(cPrime, outputCPrime, "The proof signature output cPrime was not equal to the set challenge.");
		
		BigInteger order = extendedKeyPair.getPrivateKey().getOrder();
		assertEquals(tilded.subtract(cPrime.multiply(oracle.computeDforSignature(testSigma))).mod(order), outputHatd);
	}

	@Test
	void testComputeChallenge() throws ProofStoreException, NoSuchAlgorithmException {
		prover.executePreChallengePhase();
		BigInteger cPrime = prover.computeChallenge();
		assertNotNull(cPrime);
	}

}
