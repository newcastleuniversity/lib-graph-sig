package eu.prismacloud.primitives.zkpgs.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;


@TestInstance(Lifecycle.PER_CLASS)
class GSSignatureValidatorTest {

	private SignerKeyPair signerKeyPair;
	private KeyGenParameters keyGenParameters;
	private GSSigningOracle oracle;
	private BigInteger testM;
	private GSSignature sigmaM;
	private GSSignature sigmaBlinded;
	private GroupElement Q;
	private ProofStore<Object> proofStore;
	private GSSignatureValidator validatorM;
	private GSSignatureValidator validatorBlinded;

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
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());

		sigmaM = oracle.sign(testM);
		
		sigmaBlinded = sigmaM.blind();
		
		
		
		Q = oracle.computeQforSignature(sigmaM);
		
		proofStore = new ProofStore<Object>();
		validatorM = new GSSignatureValidator(sigmaM, signerKeyPair.getPublicKey(), proofStore);
		validatorBlinded = new GSSignatureValidator(sigmaM, signerKeyPair.getPublicKey(), proofStore);
	}

	@Test
	void testComputeQ() throws ProofStoreException {
		assertEquals(Q, validatorM.computeQ(), "Q was not computed correctly.");
		assertEquals(Q, validatorBlinded.computeQ(), "Q was not computed correctly for a blinded signature.");
	}

	@Test
	void testVerify() throws ProofStoreException {
		assertTrue(validatorM.verify());
		assertTrue(validatorBlinded.verify());
	}

}
