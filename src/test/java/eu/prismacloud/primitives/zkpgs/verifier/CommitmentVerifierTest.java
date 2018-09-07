package eu.prismacloud.primitives.zkpgs.verifier;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
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
public class CommitmentVerifierTest {

	public static final int PROVER_INDEX = 1;

	private SignerKeyPair skp;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private ExtendedPublicKey epk;
	private ProofStore<Object> proofStore;
	private BigInteger testM;
	private BaseRepresentation baseR;
	private BaseCollectionImpl baseCollection;
	private CommitmentVerifier cverifier;
	private CommitmentProver cprover;
	private BigInteger tilder_i;
	private BigInteger hatr_i;
	private BigInteger cChallenge;
	private BigInteger hatm_i;
	private GroupElement tildeC_i;

	@BeforeAll
	void setUpKey() throws IOException, ClassNotFoundException, EncodingException {
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
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());

		baseR = new BaseRepresentation(epk.getPublicKey().getBaseR(), -1, BASE.BASER);
		baseR.setExponent(testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR);


		BigInteger r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());

		GSCommitment C_i = GSCommitment.createCommitment(baseCollection, r_i, epk);

		cprover = new CommitmentProver(C_i, PROVER_INDEX, extendedKeyPair.getPublicKey(), proofStore);

		// Establishing tilde- and hat-values for the message
		String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, PROVER_INDEX);
		BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		proofStore.store(tildem_iURN, tildem_i);

		cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		String hatm_iURN = URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, PROVER_INDEX);
		hatm_i = tildem_i.add(cChallenge.multiply(testM));
		proofStore.store(hatm_iURN, tildem_i);


		// Running the commitment prover
//		String tildeC_iURN = URNType.buildURNComponent(URNType.TILDECI, CommitmentProver.class);
		tildeC_i = cprover.executePreChallengePhase();

		
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, PROVER_INDEX);
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);

		
		Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);
		
		
		String hatr_iURN = URNType.buildURNComponent(URNType.HATRI, CommitmentProver.class, PROVER_INDEX);
		hatr_i = responses.get(URN.createZkpgsURN(hatr_iURN));
		gslog.info("hatr_i: " + hatr_i);
		
		// Creating a tested verifier.
		cverifier = new CommitmentVerifier(STAGE.VERIFYING, epk, proofStore);
	}



	@Test
	@DisplayName("Test witness computation for the commitment verifier")
	void computeWitness() throws VerificationException {
		fail("Testcase is faulty, should not work on base index.");
		gslog.info("compute witness");
		GroupElement hatC_i =
				cverifier.computeWitness(
						cChallenge,
						baseR);

		assertNotNull(hatC_i);
		assertEquals(tildeC_i, hatC_i);
	}

	@Test
	void testCheckLengths() throws VerificationException {
		fail("Testcase is faulty, should not work on base index.");
		gslog.info("compute witness");
		GroupElement hatC_i =
				cverifier.computeWitness(
						cChallenge,
						baseR);

		boolean isCorrectLength = cverifier.checkLengthsVerifying(baseR);

		assertTrue(isCorrectLength);
	}

	@Test
	void testComputeHatC() {
		fail("Test not implemented yet.");
	}

	@Test
	void testComputeUHat() {
		fail("Test not implemented yet.");
	}
}
