package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
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
        assertEquals(g.modPow(rho, gamma), BigInteger.ONE.mod(gamma));

    }

    @Test
    @DisplayName("compute commitment group modulus")
    void computeCommitmentGroupModulus() {
        log.info("@Test: computeCommitmentGroupModulus");
        BigInteger gamma, res;
        BigInteger rho = BigInteger.probablePrime(KeyGenParameters.l_gamma.getValue(), new SecureRandom());
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

    @Test
    @DisplayName("generate random number in range")
    void createRandomNumber() {
        log.info("@Test: createRandomNumber ");

        for (int i = 0; i < 1000; i++) {
            BigInteger rnd = classUnderTest.createRandomNumber(BigInteger.valueOf(1), BigInteger.TEN);
            log.info("random number " + i + ":  " + rnd);
            assertTrue(rnd.compareTo(BigInteger.valueOf(1)) >= 0 && rnd.compareTo(BigInteger.TEN) <= 0);
        }


    }

    @Test
    @DisplayName("generate random number in range with max,min")
    void createRandomNumberWithMaxMin() {
        log.info("@Test: createRandomNumber ");

        for (int i = 0; i < 1000; i++) {
            BigInteger rnd = classUnderTest.createRandomNumber(BigInteger.TEN, BigInteger.ZERO);
            log.info("random number " + i + ":  " + rnd);
            assertTrue(rnd.compareTo(BigInteger.valueOf(0)) >= 0 && rnd.compareTo(BigInteger.TEN) <= 0);
        }

    }

    @Test
    void elementOfQRN() {
    }

    @Test
    void verifySGeneratorOfQRN() {
    }

    @Test
    @DisplayName("generate random number with factors")
    void generateRandomNumberWithFactors() {

        log.info("@Test: generateRandomNumberWithFactors");
        BigInteger m;

        BigInteger factor;
        m = BigInteger.ONE;

        ArrayList<BigInteger> factors;

//        factors = classUnderTest.generateRandomNumberWithFactors(BigInteger.valueOf(10109));
        factors = classUnderTest.generateRandomPrimeWithFactors(new BigInteger(KeyGenParameters.l_gamma.getValue(), KeyGenParameters.l_pt.getValue(), new SecureRandom()));
        log.info("@Test: rnd length: " + factors.size());

        for (int i = 0; i < factors.size(); i++) {
            factor = factors.get(i);
            log.info("@Test: factor " + i + " : " + factor);
            assertTrue(GSUtils.isPrime(factor));
            m = m.multiply(factor);
        }

        log.info("@Test: m: " + m);
        
        log.info("@Test: m+1: " + m.add(BigInteger.ONE));
        log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
    }

    @Test
    @DisplayName("generate Prime number with factors")
    void generateRandomPrimeWithFactors() {

        BigInteger m;
        BigInteger factor;
        m = BigInteger.ONE;

        ArrayList<BigInteger> factors;

        factors = classUnderTest.generateRandomPrimeWithFactors(new BigInteger(KeyGenParameters.l_gamma.getValue(), KeyGenParameters.l_pt.getValue(), new SecureRandom()));

        log.info("@Test: rnd length: " + factors.size());

        for (int i = 0; i < factors.size(); i++) {
            factor = factors.get(i);
            log.info("@Test: factor " + i + " : " + factor);
            assertTrue(GSUtils.isPrime(factor));
            m = m.multiply(factor);
        }

        log.info("@Test: m: " + m);

        log.info("@Test: m+1: " + m.add(BigInteger.ONE));
        log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
        assertTrue(GSUtils.isPrime(m.add(BigInteger.ONE)));

    }

    @Test
    @DisplayName("get max number from a list")
    void getMaxNumber() {

        log.info("@Test: getMaxNumber" );
        ArrayList<BigInteger> list = new ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(20), BigInteger.valueOf(23), BigInteger.valueOf(19), BigInteger.valueOf(3)));

        assertEquals(BigInteger.valueOf(23), classUnderTest.getMaxNumber(list));

    }
}