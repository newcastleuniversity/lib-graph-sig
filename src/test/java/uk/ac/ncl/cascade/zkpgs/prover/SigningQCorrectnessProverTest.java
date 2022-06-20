package uk.ac.ncl.cascade.zkpgs.prover;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.SigningQCorrectnessProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.Group;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementPQ;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;

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
	 * (tilde-values) as well as the resulting witness tildeA. It retrieves these values from the ProofStore.
	 *
	 * @throws ProofStoreException if the ProofStore did not contain the required witness randomness tilded.
	 */
	@Test
	void testPreChallengePhase() throws ProofStoreException {

		tildeA = prover.executePreChallengePhase();
		tilded = (BigInteger) proofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		
		assertNotNull(tildeA, "The witness tildeA was found to be null.");
		assertNotNull(tilded, "The witness randomness for d (tilded) was found to be null.");
		
		assertEquals(Q.modPow(tilded), tildeA, "Witness tildeA was not computed correctly.");
	}
	
	/**
	 * The test case checks the post-challenge phase of the prover.
	 *
	 * @throws ProofStoreException if the ProofStore did not contain the required witness randomness tilded.
	 */
	@Test
	void testPostChallengePhase() throws ProofStoreException {

		tildeA = prover.executePreChallengePhase();
		tilded = (BigInteger) proofStore.retrieve(URNType.buildURNComponent(URNType.TILDED, SigningQCorrectnessProver.class));
		
		assertNotNull(tildeA, "The witness tildeA was found to be null.");
		assertNotNull(tilded, "The witness randomness for d (tilded) was found to be null.");
		
		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		log.info("challenge: " + cChallenge);

		
		
		Map<URN, BigInteger> responses = prover.executePostChallengePhase(cChallenge);
		BigInteger hatd = responses.get(
				URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));
		
		assertNotNull(hatd, "The response hatd was null.");
		
		BigInteger pPrime = signerKeyPair.getPrivateKey().getPPrime();
		BigInteger qPrime = signerKeyPair.getPrivateKey().getQPrime();
		BigInteger order = pPrime.multiply(qPrime);
		
		assertEquals(tilded.subtract(cChallenge.multiply(d)).mod(order), hatd, "The hatd savlue was not computed as prescribed.");
	}
	
	/**
	 * Tests the self-verification of the prover.
	 * 
	 * @throws ProofStoreException if hat-values could not be retrieved from the ProofStore.
	 * @throws NoSuchAlgorithmException If the challenge could not be obtained correctly.
	 * @throws InterruptedException If the threat was interrupted.
	 */
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
	
	
	
	@SuppressWarnings("unused")
	@Test
	void testInformationLeakagePQ() throws Exception {
		GroupElement tildeA = prover.executePreChallengePhase();
		
		try {
			QRElementPQ tildeAPQ = (QRElementPQ) tildeA;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeA contained secret information PQ.");
	}
	
	@SuppressWarnings("unused")
	@Test
	void testInformationLeakageGroupPQ() throws Exception {
		GroupElement tildeA = prover.executePreChallengePhase();
		Group tildeAGroup = tildeA.getGroup();
		try {
			QRGroupPQ tildeAGroupPQ = (QRGroupPQ) tildeAGroup;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeA contained secret group QRGroupPQ.");
	}
	
	@Test
	void testInformationLeakageOrder() throws Exception {
		GroupElement tildeA = prover.executePreChallengePhase();
		
		try {
			@SuppressWarnings("unused")
			BigInteger tildeAOrder = tildeA.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeA leaked the element order.");
	}
}
