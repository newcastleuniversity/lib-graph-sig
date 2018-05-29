package eu.prismacloud.primitives.grs.utils.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.prismacloud.primitives.zkpgs.util.crypto.EEAlgorithm;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test Extended Euclidean Algorithm */
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

    BigInteger a = BigInteger.valueOf(5);
    BigInteger b = BigInteger.valueOf(1219);

    EEAlgorithm.computeEEAlgorithm(a, b);

    log.info("modInverse b a : " + b.modInverse(a));
    log.info("modInverse a b : " + a.modInverse(b));
    log.info("mod: " + a.mod(b));
    log.info("gcd: " + a.gcd(b));
    log.info("gcd eea : " + EEAlgorithm.getD());
    log.info("S: " + EEAlgorithm.getS());
    log.info("T: " + EEAlgorithm.getT());

    assertEquals(a.gcd(b), EEAlgorithm.getD());
    //        assertEquals(BigInteger.ONE, EEAlgorithm.getS());
    //        assertEquals(BigInteger.valueOf(-2), EEAlgorithm.getT());
    // check Bezout's Identity to test EEA algorithm \( ax + by = gcd(a,b) \)
    assertEquals(a.gcd(b), a.multiply(EEAlgorithm.getS()).add(b.multiply(EEAlgorithm.getT())));

    a = BigInteger.valueOf(1219);
    b = BigInteger.valueOf(5);

    EEAlgorithm.computeEEAlgorithm(a, b);

    log.info("modInverse b a : " + b.modInverse(a));
    log.info("modInverse a b : " + a.modInverse(b));
    log.info("mod: " + a.mod(b));
    log.info("gcd: " + a.gcd(b));
    log.info("gcd eea : " + EEAlgorithm.getD());
    log.info("S: " + EEAlgorithm.getS());
    log.info("T: " + EEAlgorithm.getT());

    assertEquals(a.gcd(b), EEAlgorithm.getD());
    //        assertEquals(BigInteger.ONE, EEAlgorithm.getS());
    //        assertEquals(BigInteger.valueOf(-2), EEAlgorithm.getT());
    // check Bezout's Identity to test EEA algorithm \( ax + by = gcd(a,b) \)
    assertEquals(a.gcd(b), a.multiply(EEAlgorithm.getS()).add(b.multiply(EEAlgorithm.getT())));
  }
}
