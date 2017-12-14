package eu.prismacloud.primitives.grs.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test Extended Euclidean Algorithm  
 */
class EEAlgorithmTest {

    private static final Logger log = Logger.getLogger(EEAlgorithmTest.class.getName());

    private EEAlgorithm classUnderTest;

    @BeforeEach
    void setUp() {
//        classUnderTest = new EEAlgorithm();

    }

    @Test
    @DisplayName("Test Extended Euclidean Algorithm")
    void computeEEAlgorithm() {
        log.info("@Test: Extended Euclidean Algorithm");
        EEAlgorithm.computeEEAlgorithm(BigInteger.valueOf(100), BigInteger.valueOf(35));
        log.info("gcd: " + BigInteger.valueOf(100).gcd(BigInteger.valueOf(35)));
        
        assertEquals(BigInteger.valueOf(5), EEAlgorithm.getD());// check gcd
        assertEquals(BigInteger.valueOf(-1), EEAlgorithm.getS()); // check modInverse
        assertEquals(BigInteger.valueOf(3), EEAlgorithm.getT()); // check


    }
}