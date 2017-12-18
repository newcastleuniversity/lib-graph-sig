package eu.prismacloud.primitives.grs.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test CRT computations
 */
class CRTTest {

    private static final Logger log = Logger.getLogger(CRTTest.class.getName());

    private CRT classUnderTest;

    private BigInteger a;
    private BigInteger p;
    private BigInteger b;
    private BigInteger q;
    private BigInteger x;

    @BeforeEach
    void setUp() {
        /*
         * (\ x \equiv 2 mod 3 \)
         * (\ x \equiv 3 mod 5 \)
         *
         */
        a = BigInteger.valueOf(2);
        p = BigInteger.valueOf(3);
        b = BigInteger.valueOf(3);
        q = BigInteger.valueOf(5);
        x = BigInteger.valueOf(8);
    }

    @Test
    @DisplayName("Test Chinese Remainder Theorem")
    void computeCRT() {
        log.info("@Test: computeCRT");

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));

        BigInteger res = CRT.computeCRT(a, p, b, q);
        log.info("result: " + res);

        assertEquals(BigInteger.valueOf(8), res);

    }

    @Test
    @DisplayName("Test convert to modulo N representation ")
    void convertToModuloN() {

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));

        BigInteger res = CRT.convertToModuloN(a, p, b, q);
        log.info("result: " + res);

        assertEquals(BigInteger.valueOf(8), res);


    }

    @Test
    @DisplayName("Test convert to pq representation ")
    void convertToPQ() {

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));

        CRT.PQRepresentation crt = CRT.convertToPQ(x, p, q);
        log.info("representation 0: " + crt.getXp());
        log.info("representation 1: " + crt.getXq());

        assertEquals(a, crt.getXp());
        assertEquals(b, crt.getXq());

    }
}