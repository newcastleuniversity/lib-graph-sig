package eu.prismacloud.primitives.zkpgs.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.encoding.GeoLocationGraphEncoding;
import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.GraphUtils;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GraphPossessionVerifierTest {
	
	private Logger log = GSLoggerConfiguration.getGSlog();

	private SignerKeyPair signerKeyPair;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proofStore;
	private PossessionVerifier verifier;
	private PossessionProver prover;
	private GSSigningOracle oracle;
	private ExtendedPublicKey epk;
	private BigInteger testM;
	private GSSignature sigmaG;
	private BaseCollection baseCollection;
	private BigInteger cChallenge;

	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private GroupElement tildeZ;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		epk = extendedKeyPair.getExtendedPublicKey();

		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}

	@BeforeEach
	void setUp() throws Exception {
		proofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		GraphRepresentation gr = GraphUtils.createGraph(DefaultValues.SIGNER_GRAPH_FILE, testM, epk);
		baseCollection = gr.getEncodedBaseCollection();
		
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
		
		
		log.info("Computing a PossessionProof to be verified.");
		prover = new PossessionProver(sigmaG, epk, proofStore);
		tildeZ = prover.executePreChallengePhase();

		cChallenge = prover.computeChallenge();
		prover.executePostChallengePhase(cChallenge);

		storeVerifierView(sigmaG.getA());
		
		// Setting up a separate base collection for the verifier side, exponents purged.
		BaseCollection verifierBaseCollection = baseCollection.clone();
		verifierBaseCollection.removeExponents();
		log.info("||Verifier collection: " 
		+ GraphUtils.iteratedGraphToExpString(verifierBaseCollection.createIterator(BASE.ALL).iterator(), 
				proofStore));

		verifier = new PossessionVerifier(verifierBaseCollection, epk, proofStore);
	}

  /** The test checks whether the PossessionVerifier computes hatZ correctly. */
	@Test
	void testComputeHatZ() throws Exception {
		log.info("Checking the verifier's computation of hatZ");
    GroupElement hatZ = verifier.executeVerification(cChallenge);
    assertEquals(
        tildeZ,
        hatZ,
        "The hatZ computed by the verifier is not equal to the prover's witness tildeZ.");
	}

	/**
   * The test checks whether the PossessionVerifier correctly aborts when inputs (hat-values) with
   * wrong lengths are used. The critical case is that the lengths may be longer than asked for.
	 */
	@Test
  void testIllegalLengths() throws Exception {
		// Compute hat-values that are too long and store them in the ProofStore.
		log.info("Replacing correct hat-values with oversized ones.");
		hate = hate.multiply(BigInteger.TEN);
		hatvPrime = hatvPrime.multiply(BigInteger.TEN);
		hatm_0 = hatm_0.multiply(BigInteger.TEN);

		proofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.hate"));
		proofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.hatvPrime"));
		proofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.hatm_0"));
		proofStore.store("verifier.hate", hate);
		proofStore.store("verifier.hatvPrime", hatvPrime);
		proofStore.store("verifier.hatm_0", hatm_0);

		log.info("Testing whether the verifier correctly aborts on over-sized hat-values");
    GroupElement hatZ = verifier.executeVerification(cChallenge);

    assertNull(
        hatZ,
        "The PossionVerifier should have aborted outputting null "
				+ "upon receiving ill-sized inputs, but produced a non-null output.");
	}

	private void storeBlindedGS(GSSignature sigma) throws Exception {
		String blindedGSURN = "prover.blindedgs";
		proofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.APrime";
		proofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.ePrime";
		proofStore.store(ePrimeURN, sigma.getEPrime());

		String vPrimeURN = "prover.blindedgs.vPrime";
		proofStore.store(vPrimeURN, sigma.getV());
	}

	private void storeVerifierView(GroupElement aPrime) throws Exception {
		log.info("Retrieving hat-values");
		hate = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATE));
		hatvPrime = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATVPRIME));
		hatm_0 = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATM0));
		proofStore.store("verifier.hate", hate);
		proofStore.store("verifier.hatvPrime", hatvPrime);
		proofStore.store("verifier.hatm_0", hatm_0);
		
		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		while (vertexIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) vertexIter.next();
			
			BigInteger hatm = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATMI, base.getBaseIndex()));
			Assert.notNull(hatm, "ProofStore did not contain expected prover hat-value: " + base.getBaseIndex());
			
			proofStore.store(URNType.buildURNComponent(URNType.HATMI, PossessionVerifier.class, base.getBaseIndex()), hatm);
		}

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		while (edgeIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) edgeIter.next();
			BigInteger hatm = (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATMIJ, base.getBaseIndex()));
			Assert.notNull(hatm, "ProofStore did not contain expected prover hat-value: " + base.getBaseIndex());
			
			proofStore.store(URNType.buildURNComponent(URNType.HATMIJ, PossessionVerifier.class, base.getBaseIndex()), hatm);
		}

		proofStore.store("verifier.c", cChallenge);
		proofStore.store("verifier.APrime", aPrime);
	}
}
