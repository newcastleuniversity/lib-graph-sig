package uk.ac.ncl.cascade.zkpgs.prover;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.CommitmentProver;
import uk.ac.ncl.cascade.zkpgs.prover.PossessionProver;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.*;
import uk.ac.ncl.cascade.zkpgs.util.crypto.Group;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementPQ;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class CommitmentProverTest {
	private Logger log = GSLoggerConfiguration.getGSlog();

	private static final int PROVER_INDEX = 1;
	
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private SignerKeyPair skp;
	private ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey epk;
	private BigInteger testM;
	private ProofStore<Object> proofStore;

	private BaseCollection baseCollection;
	private CommitmentProver cprover;

	private BigInteger r_i;
	//  private GSUtils gsUtils;

	private BigInteger tildem_i;
	private BaseRepresentation baseR;
	private BigInteger tilder_i;

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
		r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());

		tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		proofStore.save(URNType.buildURN(URNType.TILDEMI, PossessionProver.class, PROVER_INDEX), tildem_i);

		baseR = new BaseRepresentation(epk.getPublicKey().getBaseR(), -1, BASE.BASER);
		baseR.setExponent(testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR);

		GSCommitment C_i = GSCommitment.createCommitment(baseCollection, r_i, epk);

		cprover = new CommitmentProver(C_i, PROVER_INDEX, extendedKeyPair.getPublicKey(), proofStore);
	}


	@Test
	@DisplayName("Test pre challenge phase for the commitment prover during issuing")
	void testPrechallengePhase() {


	}

	@Test
	@DisplayName("Test pre challenge phase for the commmimtment prover during proving")
	void testPreChallengePhaseProving() throws ProofStoreException {
		GroupElement tildeC_i = cprover.executePreChallengePhase();

		assertNotNull(tildeC_i);
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, cprover.getCommitmentIndex());
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
		assertNotNull(tilder_i);
	}

	@Test
	@DisplayName("Test witness randomness is in the correct range")
	void testCreateWitnessRandomness() throws ProofStoreException {
		cprover.executePreChallengePhase();

		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, cprover.getCommitmentIndex());
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
		assertNotNull(tilder_i);

		int l_tilderi = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

		BigInteger maxTilderi = NumberConstants.TWO.getValue().pow(l_tilderi);
		BigInteger minTilderi = maxTilderi.negate();

		assertTrue(CryptoUtilsFacade.isInRange(tilder_i, minTilderi, maxTilderi));
	}

	@Test
	void testComputeWitness() throws ProofStoreException {

		GroupElement tildeC_i = cprover.executePreChallengePhase();

		assertNotNull(tildeC_i);
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, cprover.getCommitmentIndex());
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
		assertNotNull(tilder_i);

		GroupElement baseS = epk.getPublicKey().getBaseS();
		GroupElement baseR = epk.getPublicKey().getBaseR();
		GroupElement comm = baseR.modPow(tildem_i).multiply(baseS.modPow(tilder_i));

		assertEquals(comm, tildeC_i);
	}

	@Test
	void testPostChallengePhase() throws ProofStoreException {
		
		GroupElement tildeC_i = cprover.executePreChallengePhase();

		assertNotNull(tildeC_i);
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, cprover.getCommitmentIndex());
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
		assertNotNull(tilder_i);
		
		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		
		Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);

		assertNotNull(responses);
		assertTrue(responses.size() > 0);
	}
	
	@Test
	void testProverSelfVerification() throws ProofStoreException {
		GroupElement tildeC_i = cprover.executePreChallengePhase();

		assertNotNull(tildeC_i);
		String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, cprover.getCommitmentIndex());
		gslog.info("tilder_iUrn: " + tilder_iURN);
		tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
		assertNotNull(tilder_i);
		
		BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
		
		Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);
		
		String hatm_iURN = URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, PROVER_INDEX);
		BigInteger hatm_i = tildem_i.add(cChallenge.multiply(testM));
		proofStore.store(hatm_iURN, hatm_i);
		
		assertTrue(cprover.verify(), "The commitment prover's self-verification failed.");
	}
	
	@Test
	void testInformationLeakagePQ() throws Exception {
		GroupElement tildeC_i = cprover.executePreChallengePhase();
		
		try {
			@SuppressWarnings("unused")
			QRElementPQ tildeC_iPQ = (QRElementPQ) tildeC_i;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeC_i contained secret information PQ.");
	}
	
	@Test
	void testInformationLeakageGroupPQ() throws Exception {
		GroupElement tildeC_i = cprover.executePreChallengePhase();
		Group tildeC_iGroup = tildeC_i.getGroup();
		try {
			@SuppressWarnings("unused")
			QRGroupPQ tildeC_iGroupPQ = (QRGroupPQ) tildeC_iGroup;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeC_i contained secret group QRGroupPQ.");
	}
	
	@Test
	void testInformationLeakageOrder() throws Exception {
		GroupElement tildeC_i = cprover.executePreChallengePhase();
		
		try {
			@SuppressWarnings("unused")
			BigInteger tildeC_iOrder = tildeC_i.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeC_i leaked the element order.");
	}
}
