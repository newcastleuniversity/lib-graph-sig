package eu.prismacloud.primitives.zkpgs.orchestrator;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;

@TestInstance(Lifecycle.PER_CLASS)
class SigningQVerifierOrchestratorTest {

	private SignerKeyPair gsk;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private GSSigningOracle oracle;
	private BigInteger randomM;
	private GSSignature testSigma;
	private BigInteger n_2;
	private ProofStore<Object> proverProofStore;
	private SigningQProverOrchestrator prover;
	private ProofStore<Object> verifierProofStore;
	private SigningQVerifierOrchestrator verifier;
	private BigInteger proverCPrime;
	private BigInteger tilded;
	private BigInteger hatd;

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
		proverProofStore = new ProofStore<Object>();
		
		randomM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());

		testSigma = this.oracle.sign(randomM);
		
		n_2 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		
		proverProofStore.store("issuing.signer.Q", oracle.computeQforSignature(testSigma));
		proverProofStore.store("issuing.signer.d", oracle.computeDforSignature(testSigma));
		
		prover = new SigningQProverOrchestrator(testSigma, n_2, extendedKeyPair, proverProofStore);
		
		// Running the prover.
		prover.init();
		prover.executePreChallengePhase();
		tilded = (BigInteger) proverProofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		
		
		proverCPrime = prover.computeChallenge();
		
		prover.executePostChallengePhase(proverCPrime);
		ProofSignature P_2 = prover.createProofSignature();
		assertNotNull(P_2, "The proof signature P_2 was found null.");
		hatd = (BigInteger) P_2.getProofSignatureElements().get(URN.createZkpgsURN("P_2.hatd"));
		
		
		verifierProofStore = new ProofStore<Object>();
		verifierProofStore.store("issuing.recipient.Q", oracle.computeQforSignature(testSigma));
		
		
		verifier = new SigningQVerifierOrchestrator(P_2, testSigma, n_2, extendedKeyPair.getExtendedPublicKey(), verifierProofStore);
		verifier.init();
	}

	@Test
	void testCheckLengths() {
		verifier.checkLengths();
	}
	
	// TODO check illegal lengths.

	@Test
	void testComputeChallenge() throws NoSuchAlgorithmException, ProofStoreException {
		verifier.executeVerification(proverCPrime);
		
		BigInteger verifierCPrime = verifier.computeChallenge();
		
		assertEquals(proverCPrime, verifierCPrime);
	}

	@Test
	void testExecuteVerification() throws NoSuchAlgorithmException, ProofStoreException {
		verifier.executeVerification(proverCPrime);
		
		
	}

}
