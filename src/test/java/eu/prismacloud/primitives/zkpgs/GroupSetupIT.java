package eu.prismacloud.primitives.zkpgs;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Group Setup integration testing using a 2048 modulus length with a persisted SignerKeyPair. */
@TestInstance(Lifecycle.PER_CLASS)
public class GroupSetupIT {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private ExtendedKeyPair extendedKeyPair;
	private SignerKeyPair gsk;
	private GroupSetupProver groupSetupProver;
	private ProofStore<Object> proofStore;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		gsk = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
	}

	private int computeBitLength() {
		return keyGenParameters.getL_n()
				+ keyGenParameters.getL_statzk()
				+ keyGenParameters.getL_H()
				+ 1;
	}

	@Test
	void testGroupSetup()
			throws ProofStoreException, NoSuchAlgorithmException, IOException, ClassNotFoundException, VerificationException, EncodingException {
		extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		assertNotNull(extendedKeyPair.getExtendedPublicKey());

		testGroupSetupProver();

		ProofSignature proofSignature = groupSetupProver.outputProofSignature();
		Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
		assertNotNull(proofSignature);
		assertNotNull(proofSignature.getProofSignatureElements());

		for (Object element : proofElements.values()) {
			assertNotNull(element);
		}

		int bitLength = computeBitLength();

		BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
		assertEquals(bitLength, phatr.bitLength() + 1);

		BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
		assertEquals(bitLength, phatr_0.bitLength() + 1);
		BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
		assertEquals(bitLength, phatr_Z.bitLength() + 1);

		Map<URN, BigInteger> edgeResponses =
				(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
		Map<URN, BigInteger> vertexResponses =
				(Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

		for (BigInteger vertexResponse : vertexResponses.values()) {
			assertEquals(bitLength, vertexResponse.bitLength() + 1);
		}

		for (BigInteger edgeResponse : edgeResponses.values()) {
			assertEquals(bitLength, edgeResponse.bitLength() + 1);
		}

		testGroupSetupVerifier(proofSignature);
	}

	private void testGroupSetupVerifier(ProofSignature proofSignature)
			throws NoSuchAlgorithmException, VerificationException {
		// TODO needs to be updated to Orchestrator / Verifier composition.
		GroupSetupVerifier groupSetupVerifier = new GroupSetupVerifier(proofSignature, extendedKeyPair.getExtendedPublicKey(), proofStore);
		groupSetupVerifier.checkLengths();


		fail("Test not implemented yet.");
	}

	private void testGroupSetupProver() throws NoSuchAlgorithmException, ProofStoreException {

    proofStore = new ProofStore<Object>();
		groupSetupProver = new GroupSetupProver(extendedKeyPair, proofStore);
		groupSetupProver.executeCompoundPreChallengePhase();
		BigInteger tilder =
				(BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

		BigInteger tilder_0 =
				(BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

		BigInteger tilder_Z =
				(BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

		assertNotNull(tilder);
		assertNotNull(tilder_0);
		assertNotNull(tilder_Z);

		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());;

		assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

		groupSetupProver.executePostChallengePhase(cChallenge);

		BigInteger hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
		BigInteger hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
		BigInteger hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

		assertNotNull(hatr_Z);
		assertNotNull(hatr);
		assertNotNull(hatr_0);

		int bitLength = computeBitLength();

		assertEquals(bitLength, hatr_Z.bitLength() + 1);
		assertEquals(bitLength, hatr.bitLength() + 1);
		assertEquals(bitLength, hatr_0.bitLength() + 1);
	}
}
