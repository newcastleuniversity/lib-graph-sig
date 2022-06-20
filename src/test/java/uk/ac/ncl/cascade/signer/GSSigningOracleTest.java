package uk.ac.ncl.cascade.signer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;



/** */
@TestInstance(Lifecycle.PER_CLASS)
public class GSSigningOracleTest {
	private GSSigningOracle oracle;
	private SignerKeyPair signerKeyPair;
	private KeyGenParameters keyGenParameters;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		keyGenParameters = baseTest.getKeyGenParameters();

		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}


	@Test
	void testGenerateSigningE() {
		gslog.info("GSSigningOracle: test generating signing exponent e");
		BigInteger testE = this.oracle.generateSigningE();

		assertNotNull(testE);
		assertTrue(testE.isProbablePrime(80), "Signing exponent e was not created a prime number.");
		gslog.info("GSSigningOracle:  prime e: " + testE);
	}

	@Test
	void testGenerateBlindingV() {
		gslog.info("GSSigningOracle: test generating fresh blinding randomness v");
		BigInteger testV = this.oracle.generateBlindingV();

		assertNotNull(testV);
		gslog.info("GSSigningOracle:  blinding v: " + testV);
	}

	@Test
	void testComputeA() {
		gslog.info("GSSigningOracle: test computing signature A");
		// Creating a random group element as input for the test
		BigInteger randomM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
		GroupElement randomR = this.signerKeyPair.getPublicKey().getBaseS().modPow(randomM);

		GroupElement randomQ = this.signerKeyPair.getPublicKey().getBaseZ().multiply(randomR.modInverse()); 
		BigInteger randomE = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e()-1, keyGenParameters.getL_e());

		GroupElement testA = this.oracle.computeA(randomQ, randomE);

		assertNotNull(testA);
		assertEquals(randomQ, testA.modPow(randomE));

		gslog.info("GSSigningOracle:  signature A: " + testA);
	}


	@Test
	void testSignGE() {
		gslog.info("GSSigningOracle: test signing a random group element Y");
		
		// Creating a random group element to be signed
		BigInteger randomM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
		GroupElement randomY = this.signerKeyPair.getPublicKey().getBaseS().modPow(randomM);

		GSSignature testSigma = this.oracle.sign(randomY);

		assertNotNull(testSigma);
		assertTrue(testSigma.verify(this.signerKeyPair.getPublicKey(), randomY), 
				"The signature did not verify on the random test value Y.");
		
		gslog.info("GSSigningOracle: Completed valid signature:" 
				+ "\n   Y = " + randomY 
				+ "\n   A = " + testSigma.getA()
				+ "\n   e = " + testSigma.getE()
				+ "\n   v = " + testSigma.getV());
	}

	@Test
	void testSignM() {
		gslog.info("GSSigningOracle: test signing a random message m");
		
		// Creating a random message m to be signed
		BigInteger randomM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());

		GSSignature testSigma = this.oracle.sign(randomM);

		assertNotNull(testSigma);
		assertTrue(testSigma.verify(this.signerKeyPair.getPublicKey(), randomM), 
				"The signature did not verify on the random test message m.");
		
		gslog.info("GSSigningOracle: Completed valid signature:" 
				+ "\n   m = " + randomM 
				+ "\n   A = " + testSigma.getA()
				+ "\n   e = " + testSigma.getE()
				+ "\n   v = " + testSigma.getV());
	}

	@AfterAll
	void tearDown() {
	}
}
