package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;


class IdemixUtilsTest {
    private static final Logger log = Logger.getLogger(GSUtilsTest.class.getName());
    private IdemixUtils classUnderTest;

    @BeforeEach
    void setUp() {
        classUnderTest = new IdemixUtils();

    }

    @AfterEach
    void tearDown() {
        classUnderTest = null;
    }

    @Test
    void generateRandomSafePrime() {
    }

    @Test
    void generateSpecialRSAModulus() {
    }

    @Test
    void createQRNGenerator() {
    }

    @Test
    void createRandomNumber() {
    }

    @Test
    @DisplayName("Test generate commitment group")
    void generateCommitmentGroup() {
        log.info("@Test: generateCommitmentGroup");
        assertNotNull(classUnderTest);
        CommitmentGroup cg = classUnderTest.generateCommitmentGroup();
        log.info("rho: " + cg.getRho());
        log.info("gamma:  " + cg.getGamma());
        log.info("g: " + cg.getG());
        log.info("h: " + cg.getH());
        assertNotNull(cg);

    }
}