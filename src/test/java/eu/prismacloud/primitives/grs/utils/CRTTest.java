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
        /**
         * \( x_p \equiv 1 \bmod 5 \)
         * \( x_q \equiv 2 \bmod 3 \)
         */
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(8);
    }

    @Test
    @DisplayName("Test Chinese Remainder Theorem")
    void computeCRTPC() {
        log.info("@Test: computeCRT");

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));

        BigInteger res = CRT.computeCRT(a, BigInteger.valueOf(6), b, BigInteger.valueOf(10), p.multiply(q));
        log.info("result: " + res);

        assertEquals(BigInteger.valueOf(11), res);

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

        assertEquals(BigInteger.valueOf(11), res);

    }

    @Test
    @DisplayName("Test Chinese Remainder Theorem in Z star 15")
    void testCRTZStar15() {
        log.info("@Test: testCRTZStar15");
        BigInteger result;
        // test CRT in \( Z^*_15 = { 1, 2, 4, 7, 8, 11, 13, 14} \)

        // test 1 <-> (1,1)
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(1);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(1);

        result = CRT.computeCRT(a, p, b, q);


        log.info("result 1 <-> (1,1) " + result);
        assertEquals(x, result);


        // test 2 <-> (2,2)
        a = BigInteger.valueOf(2);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(2);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 2 <-> (2,2) " + result);
        assertEquals(x, result);


        // test 4 <-> (4,1)
        a = BigInteger.valueOf(4);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(1);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(4);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 4 <-> (4,1) " + result);
        assertEquals(x, result);


        // test 7 <-> (2,1)
        a = BigInteger.valueOf(2);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(1);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(7);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 7 <-> (2,1) " + result);
        assertEquals(x, result);

        // test 8 <-> (3,2)
        a = BigInteger.valueOf(3);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(8);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 8 <-> (3,2) " + result);
        assertEquals(x, result);

        // test 11 <-> (1,2)
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(11);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 11 <-> (1,2) " + result);
        assertEquals(x, result);


        // test 13 <-> (3,1)
        a = BigInteger.valueOf(3);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(1);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(13);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 13 <-> (3,1) " + result);
        assertEquals(x, result);

        // test 14 <-> (4,2)
        a = BigInteger.valueOf(4);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(14);

        result = CRT.computeCRT(a, p, b, q);

        log.info("result 14 <-> (4,2) " + result);
        assertEquals(x, result);

    }


    @Test
    @DisplayName("Test convert to pq representation ")
    void convertToPQ() {
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(11);
        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));
        QRElementPQ qr = new QRElementPQ(new BigInteger("2"));
        CRT.convertToPQ(qr, x, p, q);
        log.info("representation 0: " + qr.getXp());
        log.info("representation 1: " + qr.getXq());

        assertEquals(a, qr.getXp());
        assertEquals(b, qr.getXq());

    }

    @Test
    void compute1p() {
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(8);

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));
        BigInteger Y = EEAlgorithm.getT();
        BigInteger one_p = CRT.compute1p(Y, p, q);
        log.info("one_p: " + one_p);
        assertEquals(BigInteger.valueOf(6), one_p);

    }

    @Test
    void compute1q() {
        a = BigInteger.valueOf(1);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(2);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(8);

        EEAlgorithm.computeEEAlgorithm(p, q);
        log.info("crt s: " + EEAlgorithm.getS());
        log.info("crt t: " + EEAlgorithm.getT());
        log.info("crt modInverse: " + p.modInverse(q));
        BigInteger X = EEAlgorithm.getS();
        BigInteger one_q = CRT.compute1q(X, p, q);
        log.info("one_q: " + one_q);
        assertEquals(BigInteger.valueOf(10), one_q);
    }
}