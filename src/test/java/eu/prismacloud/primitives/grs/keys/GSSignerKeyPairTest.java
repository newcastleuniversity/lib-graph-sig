package eu.prismacloud.primitives.grs.keys;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test Signer Key Pair
 */
class GSSignerKeyPairTest {
    private static final Logger log = Logger.getLogger(GSSignerKeyPairTest.class.getName());
    private GSSignerKeyPair gsk;

    @BeforeEach
    void setUp() {
        // classUnderTest = new GSSignerKeyPair();
        //  gsk = GSSignerKeyPair.KeyGen();
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
        gsk = GSSignerKeyPair.KeyGen();
        assertNotNull(gsk);
        assertNotNull(gsk.getPrivateKey());
        assertNotNull(gsk.getPublicKey());

    }

    @Test
    @DisplayName("Test key generation 10 times")
    void keyGen10times() {
        log.info("@Test: keyGen10times ");
        for (int i = 0; i < 10; i++) {

            gsk = GSSignerKeyPair.KeyGen();
            assertNotNull(gsk);

        }
    }

    @Test
    void generateKeySignature() {
    }

    @Test
    void getPrivateKey() {
        log.info("@Test: getPrivateKey");
        gsk = GSSignerKeyPair.KeyGen();
        assertNotNull(gsk.getPrivateKey());

    }

    @Test
    void getPublicKey() {
        log.info("@Test: getPublickKey");
        gsk = GSSignerKeyPair.KeyGen();
        assertNotNull(gsk.getPublicKey());
    }

    @Test
    void getSignature() {
        log.info("@Test: getSignature");
    }


}