package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;

@TestInstance(Lifecycle.PER_CLASS)
class SigningQCorrectnessProverTest {
	
	private Logger log = GSLoggerConfiguration.getGSlog();

	private SignerKeyPair signerKeyPair;
	private KeyGenParameters keyGenParameters;
	private ProofStore<Object> proofStore;
	private GSSigningOracle oracle;
	private BigInteger testM;

	private GSSignature sigmaM;

	private SigningQCorrectnessProver prover;

	private GroupElement tildeA;

	private BigInteger tilded;

	private GroupElement Q;

	private BigInteger d;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		keyGenParameters = baseTest.getKeyGenParameters();
		
		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}
	
	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		sigmaM = oracle.sign(testM).blind();
		
		Q = oracle.computeQforSignature(sigmaM);
		proofStore.store("issuing.signer.Q", Q);
		
		d = oracle.computeDforSignature(sigmaM);
		proofStore.store("issuing.signer.d", d);
		
		BigInteger n_2 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		
		prover = new SigningQCorrectnessProver(sigmaM, n_2, signerKeyPair, proofStore);
	}

	/**
	 * The test case is responsible for checking the computation of the witness randomness
	 * (tilde-values). It retrieves these values from the ProofStore. The computation of the overall
	 * witness tildeZ is done in testComputeWiteness(). The correct range of the witness randomness is
	 * checked by testCreateWitnessRandomness().
	 *
	 * @throws ProofStoreException
	 */
	@Test
	void testPreChallengePhase() throws ProofStoreException {

		tildeA = prover.executePreChallengePhase();
		tilded = (BigInteger) proofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		
		assertNotNull(tildeA, "The witness tildeA was found to be null.");
		assertNotNull(tilded, "The witness randomness for d (tilded) was found to be null.");
		
		assertEquals(Q.modPow(tilded), tildeA, "Witness tildeA was not computed correctly.");
	}
	
	@Test
	void testProverSelfVerification() throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {
		tildeA = prover.executePreChallengePhase();
		
		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		log.info("challenge: " + cChallenge);

		prover.executePostChallengePhase(cChallenge);

		Thread.sleep(3000);

		log.info("Calling Prover self-verification.");
		assertTrue(prover.verify(), "PossessionProver self-verification post-challenge failed.");
	}
}
