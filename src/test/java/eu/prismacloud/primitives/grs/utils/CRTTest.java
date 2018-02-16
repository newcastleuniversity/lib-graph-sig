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
    @DisplayName("Test multiplication")
    void computeCRTmult() {
        log.info("@Test: computeCRTmult");

        BigInteger xp1, xq1, xp2, xq2, res;

        a = BigInteger.valueOf(14);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(13);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(2);

        // compute 14 * 13 modulo 15 = 2 <-> (2,2)

        res = BigInteger.valueOf(14).multiply(BigInteger.valueOf(13)).mod(BigInteger.valueOf(15));
        log.info("result multiplication: " + res);
        assertEquals(x, res);

        xp1 = a.mod(p);
        log.info("xp1: " + xp1);
        xq1 = a.mod(q);
        log.info("xq1: " + xq1);

        xp2 = b.mod(p);
        log.info("xp2: " + xp2);
        xq2 = b.mod(q);
        log.info("xq2: " + xq2);

        res = CRT.computeCRT(xp1.multiply(xp2), p, xq1.multiply(xq2), q);
        log.info("result: " + res);

        assertEquals(x, res);
    }

    @Test
    @DisplayName("Test exponentiation")
    void computeCRTexp() {
        log.info("@Test: computeCRTexp");
        BigInteger base, res, exp, n;

        a = BigInteger.valueOf(14);
        p = BigInteger.valueOf(5);
        b = BigInteger.valueOf(13);
        q = BigInteger.valueOf(3);
        x = BigInteger.valueOf(2);
        base = BigInteger.valueOf(11);
        exp = BigInteger.valueOf(53);
        n = BigInteger.valueOf(15);

        // compute 11^53 mod 15
        res = base.modPow(exp, n);
        log.info("result exponentiation: " + res);
        assertEquals(BigInteger.valueOf(11), res);

        BigInteger xp = base.modPow(exp.mod(p.subtract(BigInteger.ONE)), p);
        BigInteger xq = base.modPow(exp.mod(q.subtract(BigInteger.ONE)), q);
        res = CRT.computeCRT(xp, p, xq, q);
        log.info("result pq: " + res);
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
    @DisplayName("Test random modulo exponentiations using CRT")
    void computeCRTRandomExp() {
        log.info("@Test: computeCRTRandom");
        SpecialRSAMod specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus();

        Group qrGroupPQ = new QRGroupPQ(specialRSAMod.getP(), specialRSAMod.getQ());

        Group qrGroupN = new QRGroupN(specialRSAMod.getN());

        BigInteger upperBound = specialRSAMod.getP_prime().multiply(specialRSAMod.getQ_prime()).subtract(BigInteger.ONE);

        for (int i = 0; i < 100; i++) {

            GroupElement S = qrGroupPQ.createGenerator();
            GroupElement S_n = new QRElementN(qrGroupN, S.getValue());
            BigInteger x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

            // compute using BigIntegers modPow
            BigInteger Z, Z_pq, Z_n;
            Z = S.getValue().modPow(x_Z, specialRSAMod.getN());

            // compute using QRElementN modPow
            Z_n = S_n.modPow(x_Z, specialRSAMod.getN());

            // compute using QRElementPQ modPow
            Z_pq = S.modPow(x_Z, specialRSAMod.getN());

            assertEquals(Z, Z_pq);
            assertEquals(Z, Z_n);

            for (int j = 0; j < 100; j++) {

                x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

                // compute using BigIntegers
                BigInteger Ri = S.getValue().modPow(x_Z, specialRSAMod.getN());

                // compute using QRElementN modPow
                BigInteger Ri_n = S_n.modPow(x_Z, specialRSAMod.getN());

                // compute using QRElementPQ modPow
                BigInteger Ri_pq = S.modPow(x_Z, specialRSAMod.getN());

                assertEquals(Ri, Ri_pq);
                assertEquals(Ri, Ri_n);

            }
        }

    }


    @Test
    @DisplayName("Test random multiplications using CRT")
    void computeCRTRandomMult() {
        log.info("@Test: computeCRTRandom");
        SpecialRSAMod specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus();

        Group qrGroupPQ = new QRGroupPQ(specialRSAMod.getP(), specialRSAMod.getQ());
        Group qrGroupN = new QRGroupN(specialRSAMod.getN());

        BigInteger upperBound = specialRSAMod.getP_prime().multiply(specialRSAMod.getQ_prime()).subtract(BigInteger.ONE);

        for (int i = 0; i < 100; i++) {

            GroupElement S = qrGroupPQ.createGenerator();
            GroupElement S_n = new QRElementN(qrGroupN, S.getValue());

            BigInteger x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

            // compute using BigIntegers
            BigInteger Z, Z_n, Z_pq;
            Z = S.getValue().multiply(x_Z).mod(specialRSAMod.getN());

            // compute using QRElementN multiply
            Z_n = S_n.multiply(x_Z).mod(specialRSAMod.getN());

            // compute using QRElementPQ multiply
            Z_pq = S.multiply(x_Z).mod(specialRSAMod.getN());

            assertEquals(Z, Z_pq);
            assertEquals(Z, Z_n);

            for (int j = 0; j < 100; j++) {

//                log.info("j: " + j);
                x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

                // compute using BigIntegers multiply
                BigInteger Ri = S.getValue().multiply(x_Z).mod(specialRSAMod.getN());

                // compute using QRElementN multiply
                BigInteger Ri_n = S_n.multiply(x_Z).mod(specialRSAMod.getN());

                // compute using QRElementPQ multiply
                BigInteger Ri_pq = S.multiply(x_Z).mod(specialRSAMod.getN());

                assertEquals(Ri, Ri_pq);

                assertEquals(Ri, Ri_n);

            }


        }

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