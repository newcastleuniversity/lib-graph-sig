package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
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
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;


/** */
@TestInstance(Lifecycle.PER_CLASS)
class PossessionProverTest {

	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private Logger log = GSLoggerConfiguration.getGSlog();
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
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		skp = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.graphEncodingSetup();
		extendedKeyPair.createExtendedKeyPair();
		
		log.info("Initializing GSSigningOracle");
		oracle = new GSSigningOracle(skp, keyGenParameters, graphEncodingParameters);

		epk = extendedKeyPair.getExtendedPublicKey();
	}
	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		sigmaM = oracle.sign(testM);
		
		BaseRepresentation baseR0 =
		  new BaseRepresentation(epk.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		    baseR0.setExponent(testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR0);
		
		prover = new PossessionProver();

		storeBlindedGS(sigmaM);
	}

	@Test
	void testPreChallengePhase() {

		prover.preChallengePhase(sigmaM,
				epk, baseCollection, 
				proofStore, keyGenParameters);
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		assertNotNull(tildee);
		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		assertNotNull(tildem_0);
		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		assertNotNull(tildevPrime);
		// TODO realize iteration over graph elements
	}

	@Test
	@DisplayName("Test witness randomness is in correct range")
	void testCreateWitnessRandomness() {
		// TODO establish correct randomness length
		int bitLength =
				keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();
		log.info("maximum positive random number: " + max);
		log.info("minimum negative random number: " + min);
		log.info("bitLength: " + bitLength);

		prover.preChallengePhase(sigmaM,
				epk, baseCollection, 
				proofStore, keyGenParameters);
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		assertNotNull(tildee);
		assertTrue(inRange(tildee, min, max));

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		assertNotNull(tildem_0);
		assertTrue(inRange(tildem_0, min, max));

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		assertNotNull(tildevPrime);
		assertTrue(inRange(tildevPrime, min, max));
	}

	boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
		return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
	}

	@Test
	@DisplayName("Test computing witnesses")
	void testComputeWitness() {
		tildeZ = prover.preChallengePhase(sigmaM,
				epk, baseCollection, 
				proofStore, keyGenParameters);

		assertNotNull(tildeZ);

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		GroupElement baseSTildevPrime = epk.getPublicKey().getBaseS().modPow(tildevPrime);

		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		GroupElement aPrimeTildeE = sigmaM.getA().modPow(tildee);

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		GroupElement baseR_0TildeM0 = epk.getPublicKey().getBaseR_0().modPow(tildem_0);

		GroupElement hatZ = baseSTildevPrime.multiply(aPrimeTildeE).multiply(baseR_0TildeM0);

		assertEquals(hatZ, tildeZ, "PossessionProver Witness TildeZ was not computed correctly.");
	}

	@Test
	@DisplayName("Test challenge bitLength")
	void testComputeChallenge() throws NoSuchAlgorithmException {

		prover.preChallengePhase(sigmaM,
				epk, baseCollection, 
				proofStore, keyGenParameters);
		BigInteger cChallenge = prover.computeChallenge();
		assertEquals(keyGenParameters.getL_H(), cChallenge.bitLength());
	}

	@Test
	@DisplayName("Test post challenge phase")
	void testPostChallengePhase() throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {

		prover.preChallengePhase(sigmaM,
				epk, baseCollection, 
				proofStore, keyGenParameters);
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));

		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));

		assertNotNull(tildee);
		assertNotNull(tildem_0);
		assertNotNull(tildevPrime);

		BigInteger cChallenge = prover.computeChallenge();
		log.info("challenge: " + cChallenge);

		byte[] result = cChallenge.toByteArray();

		log.info("byte array length: " + result.length);
		log.info("challenge bitlength: " + cChallenge.bitLength());

		prover.postChallengePhase(cChallenge);
		
		Thread.sleep(3000);

		hate = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATE));
		hatvPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATVPRIME));
		hatm_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATM0));

		assertNotNull(hate);
		assertNotNull(hatvPrime);
		assertNotNull(hatm_0);

		//TODO establish the correct bit-lengths
		//    int bitLength = computeBitLength();

		log.info("hate bitLength " + hate.bitLength());
		log.info("hatvPrime bitLength " + hatvPrime.bitLength());
		log.info("hatm_0 bitLength " + hatm_0.bitLength());

		//    assertEquals(bitLength, hatr_Z.bitLength()+1);
		//    assertEquals(bitLength, hatr.bitLength()+1);
		//    assertEquals(bitLength, hatr_0.bitLength()+1);
		
		log.info("Calling Prover self-verification.");
		assertTrue(prover.verify(), "PossessionProver self-verification post-challenge failed.");

	}

	private void storeBlindedGS(GSSignature sigma) throws Exception {
		String blindedGSURN = "prover.blindedgs";
		proofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.APrime";
		proofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.ePrime";
		proofStore.store(ePrimeURN, sigma.getE());

		String vPrimeURN = "prover.blindedgs.vPrime";
		proofStore.store(vPrimeURN, sigma.getV());
	}
}
