package eu.prismacloud.primitives.zkpgs.verifier;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
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
	void setUp() throws NoSuchAlgorithmException, ProofStoreException {

		proofStore = new ProofStore<Object>();
		groupSetupProver = new GroupSetupProver(extendedKeyPair, proofStore);

		groupSetupProver.executePreChallengePhase();
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

		proofSignature = groupSetupProver.outputProofSignature();
		Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
		assertNotNull(proofSignature);
		assertNotNull(proofSignature.getProofSignatureElements());

		for (Object element : proofElements.values()) {
			assertNotNull(element);
		}

		BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");

		BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
		//    assertEquals(bitLength, phatr_0.bitLength());
		BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
		//    assertEquals(bitLength, phatr_Z.bitLength());

		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> edgeResponses =
				(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
		
		@SuppressWarnings("unchecked")
		Map<URN, BigInteger> vertexResponses =
				(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

		for (BigInteger vertexResponse : vertexResponses.values()) {
			//      assertEquals(bitLength, vertexResponse.bitLength());
		}

		for (BigInteger edgeResponse : edgeResponses.values()) {
			//      assertEquals(bitLength, edgeResponse.bitLength());
		}

    groupSetupVerifier =
        new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);
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

    // compute har_0 with wrong bitlength
    BigInteger hatr_0 =
        NumberConstants.TWO
            .getValue()
            .pow(length + 1)
            .add(NumberConstants.TWO.getValue().pow(length + 1));

    proofSignature
        .getProofSignatureElements()
        .replace(URN.createZkpgsURN("proofsignature.P.hatr_0"), hatr_0);

    GroupSetupVerifier groupSetupVerifier =
        new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);

    boolean isLengthsCorrect = groupSetupVerifier.checkLengths();

    gslog.info("checklengths: " + isLengthsCorrect);

    Assertions.assertFalse(isLengthsCorrect, "checkLengths method did not reject illegal lengths");
	}
	
	@Test
  void testHatValueComputation() {

    groupSetupVerifier.computeHatValues();
	}


	@Test
  @DisplayName("Test returning hat values for GroupSetupVerifier")
  void testExecuteMultiVerification() {
    BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

    Map<URN, GroupElement> hatValues = groupSetupVerifier.executeMultiVerification(cChallenge);

    assertNotNull(hatValues);

    assertTrue(hatValues.size() > 0);
	}
}
