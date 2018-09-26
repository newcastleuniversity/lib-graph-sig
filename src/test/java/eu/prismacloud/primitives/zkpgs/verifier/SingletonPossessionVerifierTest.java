package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
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
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class SingletonPossessionVerifierTest {

	private Logger log = GSLoggerConfiguration.getGSlog();

	private SignerKeyPair signerKeyPair;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proverProofStore;
	private ProofStore<Object> verifierProofStore;
	private PossessionVerifier verifier;
	private PossessionProver prover;
	private GSSigningOracle oracle;
	private ExtendedPublicKey epk;
	private BigInteger testM;
	private GSSignature sigmaM;
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
		proverProofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		sigmaM = oracle.sign(testM).blind();
		storeBlindedGS(sigmaM);

		BaseRepresentation baseR0 =
				new BaseRepresentation(epk.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		baseR0.setExponent(testM);

		proverProofStore.store("bases.exponent.m_0", testM);

		baseCollection = new BaseCollectionImpl();
		baseCollection.add(baseR0);

		log.info("Computing a PossessionProof to be verified.");
		prover = new PossessionProver(sigmaM, epk, proverProofStore);
		tildeZ = prover.executePreChallengePhase();
		InfoFlowUtil.doesGroupElementLeakPrivateInfo(tildeZ);

		cChallenge = prover.computeChallenge();
		prover.executePostChallengePhase(cChallenge);


		verifierProofStore = new ProofStore<Object>();
		InfoFlowUtil.doesGroupElementLeakPrivateInfo(sigmaM.getA());
		storeVerifierView(sigmaM.getA());

		// Setting up a separate base collection for the verifier side, exponents purged.
		BaseCollection verifierBaseCollection = baseCollection.clone();
		verifierBaseCollection.removeExponents();

		verifier = new PossessionVerifier(verifierBaseCollection, epk, verifierProofStore);
	}

	/**
	 * The test checks whether the PossessionVerifier computes hatZ correctly.
	 */
	@Test
	void testComputeHatZ() throws Exception {
		log.info("Checking the verifier's computation of hatZ");
		GroupElement hatZ = verifier.executeVerification(cChallenge);

		InfoFlowUtil.doesGroupElementLeakPrivateInfo(hatZ);
		InfoFlowUtil.doesGroupElementLeakPrivateInfo(tildeZ);

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

		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hate"));
		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hatvPrime"));
		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hatm_0"));
		verifierProofStore.store("verifier.responses.hate", hate);
		verifierProofStore.store("verifier.responses.hatvPrime", hatvPrime);
		verifierProofStore.store("verifier.responses.hatm_0", hatm_0);

		log.info("Testing whether the verifier correctly aborts on over-sized hat-values");
		GroupElement hatZ = verifier.executeVerification(cChallenge);
		InfoFlowUtil.doesGroupElementLeakPrivateInfo(hatZ);

		assertNull(
				hatZ,
				"The PossionVerifier should have aborted outputting null "
						+ "upon receiving ill-sized inputs, but produced a non-null output.");
	}

	private void storeBlindedGS(GSSignature sigma) throws Exception {
		String blindedGSURN = "prover.blindedgs.signature.sigma";
		proverProofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.signature.APrime";
		proverProofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.signature.ePrime";
		proverProofStore.store(ePrimeURN, sigma.getEPrime());

		String vPrimeURN = "prover.blindedgs.signature.vPrime";
		proverProofStore.store(vPrimeURN, sigma.getV());
	}

	private void storeVerifierView(GroupElement aPrime) throws Exception {
		log.info("Retrieving hat-values");
		hate = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATE));
		hatvPrime = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATVPRIME));
		hatm_0 = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATM0));

		verifierProofStore.store("verifier.responses.hate", hate);
		verifierProofStore.store("verifier.responses.hatvPrime", hatvPrime);
		verifierProofStore.store("verifier.responses.hatm_0", hatm_0);
		verifierProofStore.store("verifier.c", cChallenge);
		verifierProofStore.store("verifier.APrime", aPrime);
	}

	@Test
	void testInformationFlow() {
		BaseIterator bases = baseCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : bases) {
			InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base);
		}

		InfoFlowUtil.doesGroupElementLeakPrivateInfo(sigmaM.getA());
	}
}
