package eu.prismacloud.primitives.grs.utils;


import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test Jacobi symbol computation
 */
public class JacobiSymbolTest {
    private static final Logger log = Logger.getLogger(JacobiSymbolTest.class.getName());

//    private JacobiSymbol classUnderTest;


    @BeforeEach
    void setUp() {
        //classUnderTest = new JacobiSymbol();
    }

    @AfterEach
    void tearDown() {

    }


    @Test
    @DisplayName("Test compute Jacobi Symbol")
    void computeJacobiSymbol() {
        log.info("@Test: computeJacobiSymbol");
//        BigInteger alpha = BigInteger.valueOf(118);
//        BigInteger alpha_prime;
//        BigInteger h;
//        log.info("alpha: " + alpha);
//        h = BigInteger.valueOf(alpha.getLowestSetBit());
//        alpha_prime = alpha.shiftRight(h.intValue());
//
//        log.info("h: " + h);
//        log.info("alpha_prime: " + alpha_prime);

        assertEquals(0, JacobiSymbol.computeJacobiSymbol(BigInteger.valueOf(10), BigInteger.valueOf(25)));
//
        assertEquals(-1, JacobiSymbol.computeJacobiSymbol(BigInteger.valueOf(3), BigInteger.valueOf(19)));
//
        assertEquals(1, JacobiSymbol.computeJacobiSymbol(BigInteger.valueOf(19), BigInteger.valueOf(27)));
//
        assertEquals(0, JacobiSymbol.computeJacobiSymbol(BigInteger.valueOf(15), BigInteger.valueOf(9)));

    }


    @Test
    @DisplayName("Test splitPowerRemainder")
    void splitPowerRemainder() {
        log.info("@Test: splitPowerRemainder");
//        assertNotNull();
        BigInteger sp = JacobiSymbol.splitPowerRemainder(new BigInteger("347"));
        assertEquals(new BigInteger("91"), sp);

        BigInteger sp1 = JacobiSymbol.splitPowerRemainder(new BigInteger("23297"));
        assertEquals(new BigInteger("6913"), sp1);

    }

    @Test
    @DisplayName("Test compute Jacobi symbol BA")
    void computeJacobiSymbolBA() {
        log.info("@Test: computeJacobiSymbolBA");

        assertEquals(0, JacobiSymbol.computeJacobiSymbolBA(BigInteger.valueOf(10), BigInteger.valueOf(25)));

        assertEquals(-1, JacobiSymbol.computeJacobiSymbolBA(BigInteger.valueOf(3), BigInteger.valueOf(19)));

        assertEquals(1, JacobiSymbol.computeJacobiSymbolBA(BigInteger.valueOf(19), BigInteger.valueOf(27)));

        assertEquals(0, JacobiSymbol.computeJacobiSymbolBA(BigInteger.valueOf(15), BigInteger.valueOf(9)));

    }

}