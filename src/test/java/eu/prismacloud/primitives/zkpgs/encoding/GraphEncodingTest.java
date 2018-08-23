package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;

import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class GraphEncodingTest {
	SignerKeyPair signerKeyPair;
	ExtendedPublicKey publicKey;
	List<BigInteger> vertexBases;
	List<BigInteger> edgeBases;
	private KeyGenParameters keygenParams;
	private String signatureKey;
	private GraphEncoding gr;

	@BeforeEach
	void setUp() {}

	@Test
	void checkLengthOfArray() {
		//    int[] prArray = gr.getPrimeNumbers();
		//    System.out.println("number of primes: " + prArray.length);
		fail("Test not implemented yet.");
	}

	@Test
	void getEncodingSignature() {
		fail("Test not implemented yet.");
	}

	@Test
	void signEncoding() {
		fail("Test not implemented yet.");
	}

	@Test
	void getExtendedPrivateKey() {
		fail("Test not implemented yet.");
	}

	@Test
	void setExtendedPrivateKey() {
		fail("Test not implemented yet.");
	}

	@Test
	void getExtendedPublicKey() {
		fail("Test not implemented yet.");
	}

	@Test
	void setExtendedPublicKey() {
		fail("Test not implemented yet.");
	}

	@Test
	void encode() {
		fail("Test not implemented yet.");
	}

	@Test
	void graphEncodingSetup() {
		fail("Test not implemented yet.");
	}
}
