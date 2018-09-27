package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.InfoFlowUtil;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(Lifecycle.PER_CLASS)
class SigningQCorrectnessVerifierTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private SignerKeyPair signerKeyPair;
	private KeyGenParameters keyGenParameters;
	private ProofStore<Object> proverProofStore;
	private ProofStore<Object> verifierProofStore;
	private GSSigningOracle oracle;
	private BigInteger testM;
	private GSSignature sigmaM;
	private SigningQCorrectnessProver prover;
	private SigningQCorrectnessVerifier verifier;
	private GroupElement Q;
	private BigInteger d;
	private BigInteger hatd;
	private BigInteger cPrime;
	private GroupElement tildeA;
	private ProofSignature P_2;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		keyGenParameters = baseTest.getKeyGenParameters();
		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}

	@BeforeEach
	void setUp() throws Exception {
		proverProofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		sigmaM = oracle.sign(testM).blind();

		Q = oracle.computeQforSignature(sigmaM);
		proverProofStore.store("issuing.signer.Q", Q);

		d = oracle.computeDforSignature(sigmaM);
		proverProofStore.store("issuing.signer.d", d);

		BigInteger n_2 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		prover = new SigningQCorrectnessProver(sigmaM, n_2, signerKeyPair, proverProofStore);

		tildeA = prover.executePreChallengePhase();

		cPrime = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

		Map<URN, BigInteger> responses = prover.executePostChallengePhase(cPrime);
		hatd = responses.get(
				URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));

		P_2 = createProofSignature();

		// Store signature elements for verifier

		verifierProofStore = new ProofStore<Object>();

		verifier = new SigningQCorrectnessVerifier(P_2, sigmaM, signerKeyPair.getPublicKey(), verifierProofStore);
	}

	@Test
	void testExecuteVerification() throws ProofStoreException {
		assertEquals(tildeA, verifier.executeVerification(cPrime), "The verifier did not return the correct witness value.");
	}

	@Test
	void testCheckLengths() {
		int l_hatd = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		log.info("hatd bitlength before manipulation: " + hatd.bitLength());
		log.info("Expected max bitlength: " + l_hatd);

		hatd = hatd.add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_n() + keyGenParameters.getProofOffset() + 1));
		P_2 = createProofSignature();

		verifier = new SigningQCorrectnessVerifier(P_2, sigmaM, signerKeyPair.getPublicKey(), verifierProofStore);

		assertFalse(verifier.checkLengths(), "The verifier did not reject a hatd that was too long.");
	}

	private ProofSignature createProofSignature() {
		HashMap<URN, Object> p2ProofSignatureElements = new HashMap<URN, Object>();
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.hatd"), hatd);
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.cPrime"), cPrime);

		ProofSignature P_2 = new ProofSignature(p2ProofSignatureElements);

		return P_2;
	}

	@Test
	void testInformationFlow() {
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(sigmaM.getA()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(Q));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(tildeA));
	}
}
