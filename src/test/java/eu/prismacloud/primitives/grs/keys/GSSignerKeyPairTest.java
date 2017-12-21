package eu.prismacloud.primitives.grs.keys;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test Signer Key Pair
 */
class GSSignerKeyPairTest {
    private static final Logger log = Logger.getLogger(GSSignerKeyPairTest.class.getName());
    private GSSignerKeyPair classUnderTest;

    @BeforeEach
    void setUp() {
       // classUnderTest = new GSSignerKeyPair();
    }

    @AfterEach
    void tearDown() {
        
    }

    @Test
    void getKeyGenSignature() {
    }

    @Test
    @DisplayName("Test key generation")
    void keyGen() {
       log.info("@Test: key generation");
       GSSignerKeyPair.KeyGen();
       assertNotNull(GSSignerKeyPair.KeyGen());
    }

    @Test
    void generateKeySignature() {
    }

    @Test
    void getPrivateKey() {
    }

    @Test
    void getPublicKey() {
    }

    @Test
    void getSignature() {
    }

    @Test
    void getCommitmentGroup() {
    }
}