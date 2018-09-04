package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class SingletonPossessionProverTest {

	private Logger log = GSLoggerConfiguration.getGSlog();

	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private SignerKeyPair skp;
	private ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey epk;
	private PossessionProver prover;
	private GSSignature sigmaM;
	private BigInteger testM;
	private GSSigningOracle oracle;
	private ProofStore<Object> proofStore;
	private BaseCollection baseCollection;
	private GroupElement tildeZ;
	private BigInteger tildee;
	private BigInteger tildem_0;
	private BigInteger tildevPrime;
	private BigInteger hate;
	private BigInteger hatm_0;
	private BigInteger hatvPrime;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		skp = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();

		log.info("Initializing GSSigningOracle");
		oracle = new GSSigningOracle(skp, keyGenParameters, graphEncodingParameters);

		epk = extendedKeyPair.getExtendedPublicKey();
	}

	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		sigmaM = oracle.sign(testM).blind();

		BaseRepresentation baseR0 =
				new BaseRepresentation(epk.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		baseR0.setExponent(testM);

		proofStore.store("bases.exponent.m_0", testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR0);

		prover = new PossessionProver(sigmaM, epk, proofStore);

		storeBlindedGS(sigmaM);
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

		tildeZ = prover.executePreChallengePhase();
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		assertNotNull(tildee);
		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		assertNotNull(tildem_0);
		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		assertNotNull(tildevPrime);
		// TODO realize iteration over graph elements
	}

	/**
	 * The test checks the correct range of the witness randomness.
	 *
	 * @throws ProofStoreException
	 */
	@Test
	@DisplayName("Test witness randomness is in correct range")
	void testCreateWitnessRandomness() throws ProofStoreException {
		int bitLengthM =
				keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
		int bitLengthEPrime =
				keyGenParameters.getL_prime_e()
				+ keyGenParameters.getL_statzk()
				+ keyGenParameters.getL_H()
				+ 1;
		int bitLengthV =
				keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

		BigInteger maxM = NumberConstants.TWO.getValue().pow(bitLengthM);
		BigInteger minM = maxM.negate();
		log.info(
				"tildeM:"
						+ "\n  maximum positive random number for m: "
						+ maxM
						+ "\n  minimum negative random number for m: "
						+ minM
						+ "\n  bitLength: "
						+ bitLengthM);

		BigInteger maxE = NumberConstants.TWO.getValue().pow(bitLengthEPrime);
		BigInteger minE = maxE.negate();
		log.info(
				"tildeE:"
						+ "\n  maximum positive random number for e': "
						+ maxE
						+ "\n  minimum negative random number for e': "
						+ minE
						+ "\n  bitLength: "
						+ bitLengthEPrime);

		BigInteger maxV = NumberConstants.TWO.getValue().pow(bitLengthV);
		BigInteger minV = maxV.negate();
		log.info(
				"tildeV:"
						+ "\n  maximum positive random number for v': "
						+ maxV
						+ "\n  minimum negative random number for v': "
						+ minV
						+ "\n  bitLength: "
						+ bitLengthM);

		prover.executePreChallengePhase();
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		assertNotNull(tildee);
		assertTrue(inRange(tildee, minE, maxE));

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		assertNotNull(tildem_0);
		assertTrue(inRange(tildem_0, minM, maxM));

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		assertNotNull(tildevPrime);
		assertTrue(inRange(tildevPrime, minV, maxV));
	}

	boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
		return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
	}

	/**
	 * The test checks whether witness TildeZ is computed correctly. It has a dependency on the
	 * ProofStore, retrieving the tilde values from it.
	 *
	 * @throws ProofStoreException
	 */
	@Test
	@DisplayName("Test computing witness TildeZ")
	void testComputeWitness() throws ProofStoreException {
		log.info("PossessionProverTest: Computing witness TildeZ.");
		tildeZ = prover.executePreChallengePhase();
		assertNotNull(tildeZ);

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		GroupElement baseSTildevPrime = epk.getPublicKey().getBaseS().modPow(tildevPrime);

		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		GroupElement aPrimeTildeE = sigmaM.getA().modPow(tildee);

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		GroupElement baseR_0TildeM0 = epk.getPublicKey().getBaseR_0().modPow(tildem_0);

		GroupElement hatZ = baseSTildevPrime.multiply(aPrimeTildeE).multiply(baseR_0TildeM0);

		log.info("PossessionProverTest: Comparing tildeZ against independent computation.");
		assertEquals(hatZ, tildeZ, "PossessionProver Witness TildeZ was not computed correctly.");
	}

	//	@Test
	//	@DisplayName("Test challenge bitLength")
	//	void testComputeChallenge() throws NoSuchAlgorithmException {
	//
	//		prover.preChallengePhase(sigmaM,
	//				epk, baseCollection,
	//				proofStore, keyGenParameters);
	//		BigInteger cChallenge = prover.computeChallenge();
	//		assertEquals(keyGenParameters.getL_H(), cChallenge.bitLength());
	//	}

	/**
	 * This test establishes the correctness of the response computation (hat-values). The test
	 * executes the pre-challenge phase first and computes a random challenge subsequently.
	 *
	 * <p>After executing the post-challenge phase, the hat-values are retrieved from the ProofStore.
	 * It is checked that these hat-values are consistent with witness randomness (tilde-values) and
	 * the secrets.
	 *
	 * <p>Finally, the test case calls the self-verification of the PossessionProver for a white-box
	 * test of the verification equation on the hat values.
	 *
	 * @throws ProofStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws InterruptedException
	 */
	@Test
	@DisplayName("Test post challenge phase")
	void testPostChallengePhase()
			throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {

		prover.executePreChallengePhase();
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));

		assertNotNull(tildee);
		assertNotNull(tildem_0);
		assertNotNull(tildevPrime);

		BigInteger cChallenge = prover.computeChallenge();
		log.info("challenge: " + cChallenge);

		log.info("challenge bitlength: " + cChallenge.bitLength());

		prover.executePostChallengePhase(cChallenge);

		Thread.sleep(3000);

		log.info("Checking hat-values");
		hate = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATE));
		hatvPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATVPRIME));
		hatm_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATM0));

		assertNotNull(hate);
		assertNotNull(hatvPrime);
		assertNotNull(hatm_0);

		log.info(
				"Hat Values:"
						+ "\n   hate = "
						+ hate
						+ "\n   hatvPrime = "
						+ hatvPrime
						+ "\n   hatm_0 = "
						+ hatm_0);

		log.info("Checking correspondence between hat and tilde values");
		assertEquals(tildevPrime, hatvPrime.subtract(cChallenge.multiply(sigmaM.getV())));
		assertEquals(tildem_0, hatm_0.subtract(cChallenge.multiply(testM)));
		assertEquals(tildee, hate.subtract(cChallenge.multiply(sigmaM.getEPrime())));

		// TODO establish the correct bit-lengths
		//    int bitLength = computeBitLength();

		log.info("hate bitLength " + hate.bitLength());
		log.info("hatvPrime bitLength " + hatvPrime.bitLength());
		log.info("hatm_0 bitLength " + hatm_0.bitLength());
	}

	@Test
	void testProverSelfVerification() throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {
		prover.executePreChallengePhase();
		
		BigInteger cChallenge = prover.computeChallenge();
		log.info("challenge: " + cChallenge);

		log.info("challenge bitlength: " + cChallenge.bitLength());

		prover.executePostChallengePhase(cChallenge);

		Thread.sleep(3000);

		log.info("Calling Prover self-verification.");
		assertTrue(prover.verify(), "PossessionProver self-verification post-challenge failed.");
	}

	private void storeBlindedGS(GSSignature sigma) throws Exception {
		String blindedGSURN = "prover.blindedgs";
		proofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.APrime";
		proofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.ePrime";
		proofStore.store(ePrimeURN, sigma.getEPrime());

		String vPrimeURN = "prover.blindedgs.vPrime";
		proofStore.store(vPrimeURN, sigma.getV());
	}
}
