package uk.ac.ncl.cascade.zkpgs.prover;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.PossessionProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.GraphUtils;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import uk.ac.ncl.cascade.zkpgs.util.crypto.Group;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementPQ;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GraphPossessionProverTest {

	private Logger log = GSLoggerConfiguration.getGSlog();

	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private SignerKeyPair skp;
	private ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey epk;
	private PossessionProver prover;
	private GSSignature sigmaG;
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
		epk = extendedKeyPair.getExtendedPublicKey();

		log.info("Initializing GSSigningOracle");
		oracle = new GSSigningOracle(skp, keyGenParameters, graphEncodingParameters);
	}

	@BeforeEach
	void setUp() throws ImportException, EncodingException, ProofStoreException  {
		proofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		GraphRepresentation gr = GraphUtils.createGraph(DefaultValues.SIGNER_GRAPH_FILE, epk);
		baseCollection = gr.getEncodedBaseCollection();
		
		BaseRepresentation baseR0 =
				new BaseRepresentation(epk.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		baseR0.setExponent(testM);

		proofStore.store("bases.exponent.m_0", testM);

		baseCollection.add(baseR0);
		
		assertNotNull(baseCollection);
		assertTrue(baseCollection.size() > 0);
		log.info("Size of the base collection: " + baseCollection.size());

		Iterator<BaseRepresentation> basesVertices =
				baseCollection.createIterator(BASE.VERTEX).iterator();
		log.info("||Sigma Vertex Bases: " + GraphUtils.iteratedGraphToString(basesVertices));

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		while (vertexIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) vertexIter.next();
			log.log(
					Level.INFO,
					"BaseRepresentation[ "
							+ base.getBaseIndex()
							+ ", "
							+ base.getBaseType()
							+ "]:\n   Base: "
							+ base.getBase()
							+ "\n   Exponent: "
							+ base.getExponent());
			assertNotNull(base);
			assertNotNull(base.getBase(), "Base with index " + base.getBaseIndex() + " was null.");
			// TODO Currently the encoding still returns bases with null exponents.
			//			assertNotNull(base.getExponent(), "Exponent with base index " +
			//			base.getBaseIndex() + " was null.");
		}

		Iterator<BaseRepresentation> basesEdges = baseCollection.createIterator(BASE.EDGE).iterator();
		log.info("||Sigma Edge Bases:    " + GraphUtils.iteratedGraphToString(basesEdges));

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		while (edgeIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) edgeIter.next();
			log.log(
					Level.INFO,
					"BaseRepresentation[ "
							+ base.getBaseIndex()
							+ ", "
							+ base.getBaseType()
							+ "]:\n   Base: "
							+ base.getBase()
							+ "\n   Exponent: "
							+ base.getExponent());
			assertNotNull(base);
			assertNotNull(base.getBase(), "Base with index " + base.getBaseIndex() + " was null.");
		}

		log.info("Attempting to sign base collection.");
		sigmaG = oracle.sign(baseCollection);
		assertNotNull(sigmaG.getEncodedBases(), "Encoded bases were left null after testcase setup.");

		sigmaG = sigmaG.blind();
		assertNotNull(sigmaG.getEncodedBases(), "Encoded bases were null after blinding in testcase setup.");

		prover = new PossessionProver(sigmaG, epk, proofStore);

		storeBlindedGS(sigmaG);
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

		GroupElement tildeZ = prover.executePreChallengePhase();
		tildee = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEE));
		assertNotNull(tildee);
		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		assertNotNull(tildem_0);
		tildevPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEVPRIME));
		assertNotNull(tildevPrime);

		Vector<BaseRepresentation> usedBases = new Vector<BaseRepresentation>();
		GroupElement hatZ = epk.getPublicKey().getGroup().getOne();

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);

		for (BaseRepresentation vertexBase : vertexIter) {
			//    while (vertexIter.hasNext()) {
			//      BaseRepresentation vertexBase = (BaseRepresentation) vertexIter.next();
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMI, vertexBase.getBaseIndex()));
			assertNotNull(tildem);

			BaseRepresentation tildeBase = vertexBase.clone();
			tildeBase.setExponent(tildem);
			usedBases.add(tildeBase);

			hatZ = hatZ.multiply(vertexBase.getBase().modPow(tildem));
		}

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIter) {
			//    while (edgeIter.hasNext()) {
			//      BaseRepresentation edgeBase = (BaseRepresentation) edgeIter.next();
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMIJ, edgeBase.getBaseIndex()));
			assertNotNull(tildem);
			BaseRepresentation tildeBase = edgeBase.clone();
			tildeBase.setExponent(tildem);
			usedBases.add(tildeBase);

			hatZ = hatZ.multiply(edgeBase.getBase().modPow(tildem));
		}

		log.log(
				Level.INFO,
				"||TildeZ Test: " + GraphUtils.iteratedGraphToExpString(usedBases.iterator(), proofStore));

		GroupElement aPrimeTildee = sigmaG.getA().modPow(tildee);
		GroupElement baseR_0tildem_0 = epk.getPublicKey().getBaseR_0().modPow(tildem_0);
		GroupElement baseStildevPrime = epk.getPublicKey().getBaseS().modPow(tildevPrime);

		hatZ = hatZ.multiply(aPrimeTildee).multiply(baseR_0tildem_0).multiply(baseStildevPrime);

		assertEquals(hatZ, tildeZ, "The overall witness tildeZ was not computed as expected.");
	}

	/**
	 * The test checks the correct range of the witness randomness.
	 *
	 * @throws ProofStoreException
	 */
	@Test
	@DisplayName("Test witness randomness is in correct range")
	void testCreateWitnessRandomness() throws ProofStoreException {
		int bitLengthM = keyGenParameters.getL_m() + keyGenParameters.getProofOffset();
		int bitLengthEPrime = keyGenParameters.getL_prime_e() + keyGenParameters.getProofOffset();

		int bitLengthV = keyGenParameters.getL_v() + keyGenParameters.getProofOffset();

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

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIter) {
			//			BaseRepresentation vertexBase = (BaseRepresentation) vertexIter.next();
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMI, vertexBase.getBaseIndex()));
			assertTrue(inRange(tildem, minM, maxM));
		}


		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIter) {
			//    while (edgeIter.hasNext()) {
			//      BaseRepresentation edgeBase = (BaseRepresentation) edgeIter.next();
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMIJ, edgeBase.getBaseIndex()));
			assertTrue(inRange(tildem, minM, maxM));
		}
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
		GroupElement aPrimeTildeE = sigmaG.getA().modPow(tildee);

		tildem_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEM0));
		GroupElement baseR_0TildeM0 = epk.getPublicKey().getBaseR_0().modPow(tildem_0);

		GroupElement hatZ = baseSTildevPrime.multiply(aPrimeTildeE).multiply(baseR_0TildeM0);

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);

		for (BaseRepresentation vertexBase : vertexIter) {
			//    while (vertexIter.hasNext()) {
			//      BaseRepresentation vertexBase = (BaseRepresentation) vertexIter.next();
			if (vertexBase.getBase() != null && vertexBase.getExponent() != null) {
				BigInteger tildem =
						(BigInteger)
						proofStore.retrieve(
								prover.getProverURN(URNType.TILDEMI, vertexBase.getBaseIndex()));
				hatZ = hatZ.multiply(vertexBase.getBase().modPow(tildem));
			}
		}

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIter) {
			//    while (edgeIter.hasNext()) {
			//      BaseRepresentation edgeBase = (BaseRepresentation) edgeIter.next();
			if (edgeBase.getBase() != null && edgeBase.getExponent() != null) {
				BigInteger tildem =
						(BigInteger)
						proofStore.retrieve(prover.getProverURN(URNType.TILDEMIJ, edgeBase.getBaseIndex()));
				hatZ = hatZ.multiply(edgeBase.getBase().modPow(tildem));
			}
		}

		log.info("PossessionProverTest: Comparing tildeZ against independent computation.");
		assertEquals(hatZ, tildeZ, "PossessionProver Witness TildeZ was not computed correctly.");
	}

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

		tildeZ = prover.executePreChallengePhase();
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
		
		log.info("hate bitLength " + hate.bitLength());
		log.info("hatvPrime bitLength " + hatvPrime.bitLength());
		log.info("hatm_0 bitLength " + hatm_0.bitLength());

		log.info("Checking correspondence between hat and tilde values");
		assertEquals(tildevPrime, hatvPrime.subtract(cChallenge.multiply(sigmaG.getV())));
		assertEquals(tildem_0, hatm_0.subtract(cChallenge.multiply(testM)));
		assertEquals(tildee, hate.subtract(cChallenge.multiply(sigmaG.getEPrime())));


		log.info("Checking graph encoded responses");
		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIter) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATMI, vertexBase.getBaseIndex()));
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMI, vertexBase.getBaseIndex()));
			BigInteger m = vertexBase.getExponent();

			assertEquals(tildem, hatm.subtract(cChallenge.multiply(m)), 
					"Graph encoding response on vertex base: " + vertexBase.getBaseIndex()
					+ " was not correct. Secret exponent was: " + m);
		}


		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIter) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATMIJ, edgeBase.getBaseIndex()));
			BigInteger tildem =
					(BigInteger)
					proofStore.retrieve(prover.getProverURN(URNType.TILDEMIJ, edgeBase.getBaseIndex()));
			BigInteger m = edgeBase.getExponent();

			assertEquals(tildem, hatm.subtract(cChallenge.multiply(m)), 
					"Graph encoding response on edge base: " + edgeBase.getBaseIndex()
					+ " was not correct. Secret exponent was: " + m);
		}
	}
	
	@Test
	void testProverSelfVerification() throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {
		tildeZ = prover.executePreChallengePhase();
		assertNotNull(tildeZ);
		
		BigInteger cChallenge = prover.computeChallenge();
		log.info("challenge: " + cChallenge);

		log.info("challenge bitlength: " + cChallenge.bitLength());

		prover.executePostChallengePhase(cChallenge);

		Thread.sleep(3000);
		
		
		log.info("Calling Prover self-verification.");
		assertTrue(prover.verify(), "PossessionProver self-verification post-challenge failed.");
	}

	private void storeBlindedGS(GSSignature sigma) throws ProofStoreException  {
		String blindedGSURN = "prover.blindedgs.signature.sigma";
		proofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.signature.APrime";
		proofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.signature.ePrime";
		proofStore.store(ePrimeURN, sigma.getEPrime());

		String vPrimeURN = "prover.blindedgs.signature.vPrime";
		proofStore.store(vPrimeURN, sigma.getV());
	}
	
	@Test
	void testInformationLeakagePQ() throws Exception {
		GroupElement tildeZ = prover.executePreChallengePhase();
		
		try {
			@SuppressWarnings("unused")
			QRElementPQ tildeZPQ = (QRElementPQ) tildeZ;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeZ contained secret information PQ.");
	}
	
	@Test
	void testInformationLeakageGroupPQ() throws Exception {
		GroupElement tildeZ = prover.executePreChallengePhase();
		Group tildeZGroup = tildeZ.getGroup();
		try {
			@SuppressWarnings("unused")
			QRGroupPQ tildeZGroupPQ = (QRGroupPQ) tildeZGroup;
		} catch (ClassCastException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeZ contained secret group QRGroupPQ.");
	}
	
	@Test
	void testInformationLeakageOrder() throws Exception {
		GroupElement tildeZ = prover.executePreChallengePhase();
		
		try {
			@SuppressWarnings("unused")
			BigInteger tildeZOrder = tildeZ.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected Exception
			return;
		}
		fail("The commitment witness tildeZ leaked the element order.");
	}
}
