package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
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
class GroupSetupProverTest {



	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private Logger log = GSLoggerConfiguration.getGSlog();
	private SignerKeyPair gsk;
	private ExtendedKeyPair extendedKeyPair;
	private GroupSetupProver groupSetupProver;
	private ProofStore<Object> proofStore;
	private BigInteger tilder;
	private BigInteger tilder_0;
	private BigInteger tilder_Z;
	private BigInteger hatr_Z;
	private BigInteger hatr;
	private BigInteger hatr_0;
	private GroupElement tildeZ;

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
	}

	@BeforeEach
	void setUp() {
		proofStore = new ProofStore<Object>();
		groupSetupProver = new GroupSetupProver(extendedKeyPair, proofStore);
	}

	@Test
	void testInformationFlow() {
		// TODO Check for information flow!
		fail("Test for information flow not implemented yet.");
	}
	@Test
	void preChallengePhase() throws Exception {

		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
		assertNotNull(tilder);
		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
		assertNotNull(tilder_0);
		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
		assertNotNull(tilder_Z);
	}

	@Test
	@DisplayName("Test witness randomness is in range [-2^bitLength, 2^bitlength]")
	void createWitnessRandomness() throws Exception {
		int bitLength =
				keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();
		log.info("maximum positive random number: " + max);
		log.info("minimum negative random number: " + min);
		log.info("bitLength: " + bitLength);

		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
		assertNotNull(tilder);
		assertTrue(inRange(tilder, min, max));

		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
		assertNotNull(tilder_0);
		assertTrue(inRange(tilder_0, min, max));

		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
		assertNotNull(tilder_Z);
		assertTrue(inRange(tilder_Z, min, max));
	}

	boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
		return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
	}

	@Test
	@DisplayName("Test witness randomness bit length")
	void computeWitnessRandomnessBitLength() throws ProofStoreException {
		int bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();
		log.info("maximum positive random number: " + max);
		log.info("minimum negative random number: " + min);
		log.info("bitLength: " + bitLength);

		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
		assertNotNull(tilder);
		assertTrue(inRange(tilder, min, max));
		//    log.info("bitLength tilder: " + tilder.bitLength());
		//    assertEquals(bitLength, tilder.bitLength());

		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
		assertNotNull(tilder_0);
		assertTrue(inRange(tilder_0, min, max));
		//    log.info("bitLength tilder_0: " + tilder_0.bitLength());
		//    assertEquals(bitLength, tilder_0.bitLength());

		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
		assertNotNull(tilder_Z);
		assertTrue(inRange(tilder_Z, min, max));
		//    log.info("bitLength tilder_Z: " + tilder_Z.bitLength());
		//    assertEquals(bitLength, tilder_Z.bitLength());
	}

	@Test
	@DisplayName("Test computing witnesses")
	void computeWitness() throws ProofStoreException {
		groupSetupProver.executeCompoundPreChallengePhase();
		tildeZ = (GroupElement) proofStore.retrieve("groupsetupprover.witnesses.tildeZ");
		assertNotNull(tildeZ);
		/** TODO test that it is congruent */
	}

	@Test
	@DisplayName("Test post challenge phase")
	//  @RepeatedTest(15)
	void postChallengePhase() throws ProofStoreException, NoSuchAlgorithmException {
		int bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();

		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

		assertNotNull(tilder);
		assertNotNull(tilder_0);
		assertNotNull(tilder_Z);

		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		log.info("challenge bitlength: " + cChallenge.bitLength());

		Map<URN, BigInteger> responses = groupSetupProver.executePostChallengePhase(cChallenge);
		assertNotNull(responses);
		assertTrue(responses.size() > 0);

		hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
		hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
		hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

		assertNotNull(hatr_Z);
		assertNotNull(hatr);
		assertNotNull(hatr_0);

		assertTrue(inRange(hatr_Z, min, max));
		assertTrue(inRange(hatr, min, max));
		assertTrue(inRange(hatr_0, min, max));

		//    int bitLength = computeBitLength();
		//
		//    log.info("hatrZ bitLength " + hatr_Z.bitLength());
		//    log.info("hatr bitLength " + hatr.bitLength());
		//    log.info("hatr0 bitLength " + hatr_0.bitLength());
		//
		//    assertEquals(bitLength, hatr_Z.bitLength() + 1);
		//    assertEquals(bitLength, hatr.bitLength() + 1);
		//    assertEquals(bitLength, hatr_0.bitLength() + 1);
	}

	@Test
	@DisplayName("Test output proof signature")
	void outputProofSignature() throws NoSuchAlgorithmException, ProofStoreException {
		int bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();
		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

		assertNotNull(tilder);
		assertNotNull(tilder_0);
		assertNotNull(tilder_Z);

		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		groupSetupProver.executePostChallengePhase(cChallenge);

		hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
		hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
		hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

		assertNotNull(hatr_Z);
		assertNotNull(hatr);
		assertNotNull(hatr_0);
		assertTrue(inRange(hatr_Z, min, max));
		assertTrue(inRange(hatr, min, max));
		assertTrue(inRange(hatr_0, min, max));
		//    int bitLength = computeBitLength();
		//
		//    assertEquals(bitLength, hatr_Z.bitLength() + 1);
		//    assertEquals(bitLength, hatr.bitLength() + 1);
		//    assertEquals(bitLength, hatr_0.bitLength() + 1);

		ProofSignature proofSignature = groupSetupProver.outputProofSignature();
		Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
		assertNotNull(proofSignature);
		assertNotNull(proofSignature.getProofSignatureElements());

		for (Object element : proofElements.values()) {
			assertNotNull(element);
		}

		BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr");
		assertTrue(inRange(phatr, min, max));
		//    assertEquals(bitLength, phatr.bitLength() + 1);

		BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr_0");
		assertTrue(inRange(phatr_0, min, max));

		assertEquals(bitLength, phatr_0.bitLength() + 1);
		BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr_Z");
		assertTrue(inRange(phatr_Z, min, max));
		//    assertEquals(bitLength, phatr_Z.bitLength() + 1);

		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> vertexResponses =
		((Map<URN, BigInteger>) proofSignature.get("proofsignature.P.responses.hatr_iMap"));
		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> edgeResponses =
		((Map<URN, BigInteger>) proofSignature.get("proofsignature.P.responses.hatr_i_jMap"));

		for (BigInteger vertexResponse : vertexResponses.values()) {
			assertTrue(inRange(vertexResponse, min, max));
			//      assertEquals(bitLength, vertexResponse.bitLength() + 1);
		}

		for (BigInteger edgeResponse : edgeResponses.values()) {
			assertTrue(inRange(edgeResponse, min, max));
			//      assertEquals(bitLength, edgeResponse.bitLength() + 1);
		}
	}

	//  private int computeBitLength() {
	//    return keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
	//  }
}
