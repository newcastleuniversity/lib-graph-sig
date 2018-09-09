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
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
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
	private ProofStore<Object> proverProofStore;
	private ProofStore<Object> verifierProofStore;
	private BigInteger testM;
	private BaseRepresentation baseR;
	private BaseCollectionImpl baseCollection;
	private CommitmentVerifier cverifier;
	private CommitmentProver cprover;
	private BigInteger tilder_i;
	private BigInteger hatr_i;
	private BigInteger hatm_i;
	private GroupElement tildeC_i;

	private BigInteger cChallenge;

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
		proverProofStore = new ProofStore<Object>();
		verifierProofStore = new ProofStore<Object>();
		
		
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());

		// Establishing the commitment
		baseR = new BaseRepresentation(epk.getPublicKey().getBaseR(), -1, BASE.BASER);
		baseR.setExponent(testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR);

		BigInteger r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
		GSCommitment C_i = GSCommitment.createCommitment(baseCollection, r_i, epk);
		
		
		// New prover on commitment
		cprover = new CommitmentProver(C_i, PROVER_INDEX, extendedKeyPair.getPublicKey(), proverProofStore);

		// Establishing tilde- and hat-values for the message
		BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		proverProofStore.save(URNType.buildURN(URNType.TILDEMI, PossessionProver.class, PROVER_INDEX), tildem_i);



		// Running the commitment prover
		tildeC_i = cprover.executePreChallengePhase();
		assertNotNull(tildeC_i);
		
		
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, PROVER_INDEX);
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proverProofStore.retrieve(tilder_iURN);

		
		
		cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		assertNotNull(cChallenge);
		
		String hatm_iURN = URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, PROVER_INDEX);
		hatm_i = tildem_i.add(cChallenge.multiply(testM));
		proverProofStore.store(hatm_iURN, hatm_i);
		
		
		Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);
		
		String hatr_iURN = URNType.buildURNComponent(URNType.HATRI, CommitmentProver.class, PROVER_INDEX);
		hatr_i = responses.get(URN.createZkpgsURN(hatr_iURN));
		gslog.info("hatr_i: " + hatr_i);
		
		// Populating Verifier ProofStore
		String hatr_iURNverifier = URNType.buildURNComponent(URNType.HATRI, CommitmentVerifier.class, PROVER_INDEX);
		verifierProofStore.save(URN.createZkpgsURN(hatr_iURNverifier), hatr_i);
		
		String hatm_iURNverifier = URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, PROVER_INDEX);
		verifierProofStore.save(URN.createZkpgsURN(hatm_iURNverifier), hatm_i);
		
		// Creating a tested verifier.
		cverifier = new CommitmentVerifier(C_i.getCommitmentValue(), C_i.getBaseCollection(), PROVER_INDEX, epk, verifierProofStore);
	}

	@Test
	void testProverSelfVerification() {
		assertTrue(cprover.verify(), "The commitment prover self-serification failed.");
	}


	@Test
	@DisplayName("Test witness computation for the commitment verifier")
	void computeWitness() throws VerificationException, ProofStoreException {
		gslog.info("compute witness");
		GroupElement hatC_i = cverifier.executeVerification(cChallenge);

		assertNotNull(hatC_i);
		assertEquals(tildeC_i, hatC_i);
	}

	@Test
	void testCheckLengths() throws VerificationException, ProofStoreException {
		gslog.info("compute witness");
		try {
			GroupElement hatC_i = cverifier.executeVerification(cChallenge);
		} catch (VerificationException e) {
			fail("Length should have validated.");
		}
		
		boolean isCorrectLength = cverifier.checkLengths();

		assertTrue(isCorrectLength);
	}
}
