package uk.ac.ncl.cascade.verifier;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.PairWiseDifferenceProver;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.InfoFlowUtil;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import uk.ac.ncl.cascade.zkpgs.verifier.PairWiseDifferenceVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.*;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class PairWiseDifferenceVerifierTest {

	private Logger log = GSLoggerConfiguration.getGSlog();
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private SignerKeyPair skp;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proofStore;
	private ExtendedPublicKey epk;
	private BigInteger cChallenge;
	private PairWiseDifferenceProver prover;
	private PairWiseDifferenceVerifier verifier;
	private int testIndex;
	private BigInteger m1, m2coprime;
	private GSCommitment c1, c2coprime;
	private BigInteger hata_BariBarj, hatb_BariBarj, hatr_BariBarj;
	private GroupElement tildeR;
	private GroupElement hatR;

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

		epk = extendedKeyPair.getExtendedPublicKey();
	}

	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		int minLength = Math.floorDiv(keyGenParameters.getL_m(), 2);
		m1 = CryptoUtilsFacade.computeRandomNumber(minLength);
		c1 = GSCommitment.createCommitment(m1, epk);

		// Exponent m2coprime is guaranteed to be coprime with m1: prime number larger than m1.
		m2coprime = CryptoUtilsFacade.computePrimeWithLength(minLength + 1, keyGenParameters.getL_m());
		c2coprime = GSCommitment.createCommitment(m2coprime, epk);

		testIndex = 0;

		log.info("Computing a PairWiseDifferenceProof to be verified.");
		prover = new PairWiseDifferenceProver(c1, c2coprime, testIndex, epk, proofStore);
		prover.executePrecomputation();

		String basetildeR_BariBarjURN = "pairwiseprover.tildeBaseR_BariBarj_" + testIndex;
		Map<URN, GroupElement> witnesses = prover.executeCompoundPreChallengePhase();
		tildeR = witnesses.get(URN.createZkpgsURN(basetildeR_BariBarjURN));

		cChallenge = prover.computeChallenge();
		assertNotNull(cChallenge);
		prover.executePostChallengePhase(cChallenge);

		log.info("Retrieving hat-values");
		hata_BariBarj =
				(BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATABARIBARJ, testIndex));
		hatb_BariBarj =
				(BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATBBARIBARJ, testIndex));
		hatr_BariBarj =
				(BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATRBARIBARJ, testIndex));

		verifier = new PairWiseDifferenceVerifier(c1, c2coprime, testIndex, epk, proofStore);

		storeVerifierView(testIndex);
	}

	/**
	 * The test checks whether the PairWiseDifferenceVerifier computes hatR correctly.
	 *
	 * @throws ProofStoreException
	 */
	@Test
	void testComputeHatR() throws ProofStoreException {
		log.info("Checking the verifier's computation of hatR");

		Map<URN, GroupElement> responses = verifier.executeCompoundVerification(cChallenge);
		String hatRURN = verifier.getVerifierURN(URNType.HATR);

		hatR = responses.get(URN.createZkpgsURN(hatRURN));

		assertNotNull(verifier);
		assertNotNull(hatR);
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(hatR));
		assertEquals(
				tildeR,
				hatR,
				"The hatR computed by the verifier is not equal to the prover's witness tildeR.");
	}

	/**
	 * The test checks whether the PairWiseDifferenceVerifier correctly aborts when inputs
	 * (hat-values) with wrong lengths are used. The critical case is that the lengths may be longer
	 * than asked for.
	 */
	@Test
	void testIllegalLengths() throws Exception {
		// Compute hat-values that are too long and store them in the ProofStore.
		log.info("Replacing correct hat-values with oversized ones.");
		hata_BariBarj = hata_BariBarj.multiply(BigInteger.TEN);
		hatb_BariBarj = hatb_BariBarj.multiply(BigInteger.TEN);
		hatr_BariBarj = hatr_BariBarj.multiply(BigInteger.TEN);

		proofStore.remove(
				URN.createURN(
						URN.getZkpgsNameSpaceIdentifier(),
						verifier.getVerifierURN(URNType.HATABARIBARJ, testIndex)));
		proofStore.remove(
				URN.createURN(
						URN.getZkpgsNameSpaceIdentifier(),
						verifier.getVerifierURN(URNType.HATBBARIBARJ, testIndex)));
		proofStore.remove(
				URN.createURN(
						URN.getZkpgsNameSpaceIdentifier(),
						verifier.getVerifierURN(URNType.HATRBARIBARJ, testIndex)));
		proofStore.store(verifier.getVerifierURN(URNType.HATABARIBARJ, testIndex), hata_BariBarj);
		proofStore.store(verifier.getVerifierURN(URNType.HATBBARIBARJ, testIndex), hatb_BariBarj);
		proofStore.store(verifier.getVerifierURN(URNType.HATRBARIBARJ, testIndex), hatr_BariBarj);

		log.info("Testing whether the verifier correctly aborts on over-sized hat-values");
		Object output = verifier.executeCompoundVerification(cChallenge);

		assertNull(
				output,
				"The PairWiseDifferenceVerifier should have aborted outputting null "
						+ "upon receiving ill-sized inputs, but produced a non-null output.");
	}

	private void storeVerifierView(final int index) throws Exception {
		assertNotNull(proofStore);
		assertNotNull(verifier);
		assertNotNull(hata_BariBarj);
		assertNotNull(hatb_BariBarj);
		assertNotNull(hatr_BariBarj);
		proofStore.store(verifier.getVerifierURN(URNType.HATABARIBARJ, index), hata_BariBarj);
		proofStore.store(verifier.getVerifierURN(URNType.HATBBARIBARJ, index), hatb_BariBarj);
		proofStore.store(verifier.getVerifierURN(URNType.HATRBARIBARJ, index), hatr_BariBarj);
		proofStore.store("verifier.c", cChallenge);
	}

	@Test
	void testInformationFlow() {
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(tildeR));

	}
}
