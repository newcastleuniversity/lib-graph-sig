package eu.prismacloud.primitives.zkpgs.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Test group setup verifier */
@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupVerifierTest {

	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
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
	private GroupSetupVerifier groupSetupVerifier;
	private ProofSignature proofSignature;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private SignerPublicKey signerPubliKey;
	private BigInteger cChallenge;

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
		signerPubliKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
	}

	@BeforeEach
	void setUp() throws NoSuchAlgorithmException, ProofStoreException {
		int bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
		BigInteger min = max.negate();

		proofStore = new ProofStore<Object>();
		groupSetupProver = new GroupSetupProver(extendedKeyPair, proofStore);

		groupSetupProver.executeCompoundPreChallengePhase();
		tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

		tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

		tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

		assertNotNull(tilder);
		assertTrue(inRange(tilder, min, max));
		assertNotNull(tilder_0);
		assertTrue(inRange(tilder_0, min, max));
		assertNotNull(tilder_Z);
		assertTrue(inRange(tilder_Z, min, max));

		cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		groupSetupProver.executePostChallengePhase(cChallenge);

		hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
		hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
		hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

		assertNotNull(hatr_Z);
		assertTrue(inRange(hatr_Z, min, max));

		assertNotNull(hatr);
		assertTrue(inRange(hatr, min, max));

		assertNotNull(hatr_0);
		assertTrue(inRange(hatr_0, min, max));

		proofSignature = groupSetupProver.outputProofSignature();
		Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
		assertNotNull(proofSignature);
		assertNotNull(proofSignature.getProofSignatureElements());

		for (Object element : proofElements.values()) {
			assertNotNull(element);
		}

		BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr");
		assertTrue(inRange(phatr, min, max));

		BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr_0");
		assertTrue(inRange(phatr_0, min, max));
		//    assertEquals(bitLength, phatr_0.bitLength());
		BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.responses.hatr_Z");
		assertTrue(inRange(phatr_Z, min, max));
		//    assertEquals(bitLength, phatr_Z.bitLength());

		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> edgeResponses =
		(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.responses.hatr_i");

		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> vertexResponses =
		(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.responses.hatr_i_j");

		for (BigInteger vertexResponse : vertexResponses.values()) {
			assertTrue(inRange(vertexResponse, min, max));
			//      assertEquals(bitLength, vertexResponse.bitLength() + 1);
		}

		for (BigInteger edgeResponse : edgeResponses.values()) {
			assertTrue(inRange(edgeResponse, min, max));
			//      assertEquals(bitLength, edgeResponse.bitLength() + 1);
		}

		groupSetupVerifier =
				new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);
	}

	boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
		return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
	}

	@Test
	@DisplayName("Test bitlengths are correct")
	void testCheckLengths() {
		groupSetupVerifier =
				new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);
		assertNotNull(groupSetupVerifier);

		boolean isLengthCorrect = groupSetupVerifier.checkLengths();
		assertTrue(isLengthCorrect);
	}

	@Test
	@DisplayName("Test illegal bitlengths so that the checkLengths returns false")
	void testIllegalLengths() throws ProofStoreException {
		int length = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		gslog.info("compute bit length: " + length);
		BigInteger hatr_0 =
				(BigInteger)
				proofSignature
				.getProofSignatureElements()
				.get(URN.createZkpgsURN("proofsignature.P.responses.hatr_0"));
		hatr_0 = hatr_0.multiply(BigInteger.TEN);

		proofSignature
		.getProofSignatureElements()
		.replace(URN.createZkpgsURN("proofsignature.P.responses.hatr_0"), hatr_0);

		GroupSetupVerifier groupSetupVerifier =
				new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);

		boolean isLengthsCorrect = groupSetupVerifier.checkLengths();

		gslog.info("checklengths: " + isLengthsCorrect);

		Assertions.assertFalse(isLengthsCorrect, "checkLengths method did not reject illegal lengths");
	}

	@Test
	@DisplayName("Test responses computation for the verifier")
	void testHatValueComputation() {
		BigInteger negChallenge = cChallenge.negate();
		GroupElement baseS = signerPubliKey.getBaseS();
		GroupElement baseZ = signerPubliKey.getBaseZ();

		Map<URN, GroupElement> responses = groupSetupVerifier.computeHatValues();
		assertNotNull(responses);
		assertTrue(responses.size() > 0);

		GroupElement hatZ =
				responses.get(URN.createZkpgsURN(groupSetupVerifier.getVerifierURN(URNType.HATZ)));
		GroupElement testHatZ = baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_Z));
		assertEquals(testHatZ, hatZ);

		GroupElement tildeZ = baseS.modPow(tilder_Z);
		assertEquals(tildeZ, hatZ);

		GroupElement hatR =
				responses.get(URN.createZkpgsURN(groupSetupVerifier.getVerifierURN(URNType.HATBASER)));
		GroupElement tildeR = baseS.modPow(tilder);
		assertEquals(tildeR, hatR);

		GroupElement hatR0 =
				responses.get(URN.createZkpgsURN(groupSetupVerifier.getVerifierURN(URNType.HATBASER0)));
		GroupElement tildeR0 = baseS.modPow(tilder_0);
		assertEquals(tildeR0, hatR0);
	}

	@Test
	@DisplayName("Test returning hat values for GroupSetupVerifier")
	void testExecuteVerification() {
		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		Map<URN, GroupElement> hatValues = groupSetupVerifier.executeCompoundVerification(cChallenge);

		assertNotNull(hatValues);

		assertTrue(hatValues.size() > 0);
	}
}
