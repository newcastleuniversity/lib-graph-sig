package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test GSUtils class
 */
class GSUtilsTest {

    private static final Logger log = GSLoggerConfiguration.getGSlog();

    private GSUtils classUnderTest;

    @BeforeEach
    void setUp() {

        classUnderTest = new GSUtils();

    }

    @AfterEach
    void tearDown() {
        classUnderTest = null;
    }

    @Test
    void generateSpecialRSAModulus() {
    }

    @Test
    void createRandomNumber() {
    }

    @Test
    @DisplayName("Test generate commitment group")
    void generateCommitmentGroup() {
        log.info("@Test: generate commitment group");
        assertNotNull(classUnderTest);
        CommitmentGroup cg = classUnderTest.generateCommitmentGroup();
        assertNotNull(cg);
        log.info("rho: " + cg.getRho());
        log.info("gamma: " + cg.getGamma());
        log.info("g: " + cg.getG());
        log.info("h:" + cg.getH());


    }

    @Test
    void computeJacobiSymbol() {
    }

    @Test
    void elementOfQR() {
    }

    @Test
    void createElementOfZNS() {
    }

    @Test
    void verifySGeneratorOfZNS() {
    }

    @Test
    void createQRNGenerator() {
    }

    @Test
    void splitPowerRemainder() {
    }

    @Test
    void generateCLSignature() {
    }

    @Test
    void generateSignatureProofOfKnowledge() {
    }

    @Test
    void generateRandomSafePrime() {
    }

    @Test
    void isPrime() {
    }

    @Test
    @DisplayName("Test generate Prime")
    void generatePrime() {
        log.info("@Test: generatePrime ");
        BigInteger bg = GSUtils.generatePrime(KeyGenParameters.l_n.getValue() / 2);
        log.info("bg: " + bg);
        assertNotNull(bg);
        assertTrue(bg.isProbablePrime(80));


    }

    @Test
    void bigPow() {
    }

    @Test
    void computeJacobiSymbol1() {
    }

    @Test
    void elementOfQR1() {
    }

    @Test
    void createElementOfZNS1() {
    }

    @Test
    void verifySGeneratorOfZNS1() {
    }

    @Test
    void createQRNGenerator1() {
    }

    @Test
    void splitPowerRemainder1() {
    }

    @Test
    void generateCLSignature1() {
    }

    @Test
    void generateSignatureProofOfKnowledge1() {
    }

    @Test
    void generateRandomSafePrime1() {
    }

    @Test
    void isPrime1() {
    }

    @Test
    void generatePrime1() {
    }

    @Test
    @DisplayName("create commitment group generator")
    void createCommitmentGroupGenerator() {
        log.info("@Test: createCommitmentGroupGenerator");
        BigInteger gamma, g;
        BigInteger rho = BigInteger.probablePrime(KeyGenParameters.l_rho.getValue(), new SecureRandom());
        gamma = classUnderTest.computeCommitmentGroupModulus(rho);
        log.info("gamma: " + gamma);
        log.info("gamma bitlength: " + gamma.bitLength());
        assertNotNull(gamma);

        g = classUnderTest.createCommitmentGroupGenerator(rho, gamma);

        assertNotNull(g);
        // g^rho mod gamma = 1 mod gamma
        assertEquals(g.modPow(rho,gamma),BigInteger.ONE.mod(gamma));

    }

    @Test
    @DisplayName("compute commitment group modulus")
    void computeCommitmentGroupModulus() {
        log.info("@Test: computeCommitmentGroupModulus");
        BigInteger gamma, res;
        BigInteger rho = BigInteger.probablePrime(KeyGenParameters.l_rho.getValue(), new SecureRandom());
//        BigInteger rho = BigInteger.probablePrime(16,new SecureRandom());

        gamma = classUnderTest.computeCommitmentGroupModulus(rho);
        log.info("gamma: " + gamma);
        log.info("gamma bitlength: " + gamma.bitLength());
        assertNotNull(gamma);
        //check rho divides gamma - 1
        BigInteger ga = gamma.subtract(BigInteger.ONE);
        res = ga.divideAndRemainder(rho)[1];
        log.info("divides: " + res);
        assertEquals(BigInteger.ZERO, res);

    }
}