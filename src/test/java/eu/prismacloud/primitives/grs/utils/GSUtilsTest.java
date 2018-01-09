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

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
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
        BigInteger m = BigInteger.probablePrime(KeyGenParameters.l_gamma.getValue(), new SecureRandom());
        gamma = classUnderTest.computeCommitmentGroupModulus(m);
        log.info("gamma: " + gamma);
        log.info("gamma bitlength: " + gamma.bitLength());
        assertNotNull(gamma);

        g = classUnderTest.createCommitmentGroupGenerator(classUnderTest.getRho(), gamma);

        assertNotNull(g);
        // g^rho mod gamma = 1 mod gamma
        assertEquals(g.modPow(classUnderTest.getRho(), gamma.add(BigInteger.ONE)), BigInteger.ONE.mod(gamma.add(BigInteger.ONE)));

    }

    @Test
    @DisplayName("compute commitment group modulus")
    void computeCommitmentGroupModulus() {
        log.info("@Test: computeCommitmentGroupModulus");
        BigInteger mingamma, res;
        BigInteger m = BigInteger.probablePrime(KeyGenParameters.l_gamma.getValue(), new SecureRandom());
//        BigInteger rho = BigInteger.probablePrime(16,new SecureRandom());

        mingamma = classUnderTest.computeCommitmentGroupModulus(m);
        log.info("gamma: " + mingamma);
        log.info("gamma bitlength: " + mingamma.bitLength());
        assertNotNull(mingamma);
        //check rho divides gamma - 1 = mingamma
        res = mingamma.divideAndRemainder(classUnderTest.getRho())[1];
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

        log.info("@Test: getMaxNumber");
        ArrayList<BigInteger> list = new ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(20), BigInteger.valueOf(23), BigInteger.valueOf(19), BigInteger.valueOf(3)));

        assertEquals(BigInteger.valueOf(23), classUnderTest.getMaxNumber(list));

    }

    @Test
    @DisplayName("createZPSGenerator")
    void createZPSGenerator() {
        log.info("@Test: createZPSGenerator");
        //1150 = 2x5x5x23

//        ArrayList<BigInteger> primeFactors = new ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(2), BigInteger.valueOf(5), BigInteger.valueOf(23), BigInteger.valueOf(5)));
        
        //10 = 2x5  (generators {2,6,7,8})

        for (int i = 0; i < 1000; i++) {

            ArrayList<BigInteger> primeFactors = new ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(2), BigInteger.valueOf(5)));

            BigInteger gamma, g;

//        BigInteger rho = BigInteger.valueOf(383);
            BigInteger rho = BigInteger.valueOf(5);

            BigInteger m = BigInteger.probablePrime(KeyGenParameters.l_gamma.getValue(), new SecureRandom());

            gamma = BigInteger.valueOf(11); //classUnderTest.computeCommitmentGroupModulus(m);

            log.info("gamma: " + gamma);
            log.info("gamma bitlength: " + gamma.bitLength());
            assertNotNull(gamma);

            g = classUnderTest.createZPSGenerator(gamma, primeFactors);

            log.info("generator: " + g);

            assertNotNull(g);
            // g^rho mod gamma = 1 mod gamma
//        assertEquals(g.modPow(classUnderTest.getRho(), gamma.add(BigInteger.ONE)), BigInteger.ONE.mod(gamma.add(BigInteger.ONE)));
            assertThat(g, anyOf(is(BigInteger.valueOf(2)), is(BigInteger.valueOf(6)), is(BigInteger.valueOf(7)), is(BigInteger.valueOf(8))));
        }
    }

    @Test
    void getRho() {
    }
}