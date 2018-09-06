package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.math.BigInteger;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GSCommitmentTest {

    private GSCommitment commitment;
    private BaseCollection baseCollection;
    private BigInteger modN;
    private GroupElement R_0;
    private GroupElement R_1;
    private BigInteger m_0;
    private BigInteger m_1;
    private GroupElement R_2;
    private BigInteger m_2;
    private ExtendedPublicKey epk;
    private BigInteger randomness;

    @BeforeAll
    void setupKey() throws IOException, ClassNotFoundException, EncodingException {
        BaseTest baseTest = new BaseTest();
        baseTest.setup();
        baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
        SignerKeyPair skp = baseTest.getSignerKeyPair();
        GraphEncodingParameters graphEncodingParameters = baseTest.getGraphEncodingParameters();
        KeyGenParameters keyGenParameters = baseTest.getKeyGenParameters();
        ExtendedKeyPair extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
        extendedKeyPair.generateBases();
        extendedKeyPair.setupEncoding();
        extendedKeyPair.createExtendedKeyPair();
        epk = extendedKeyPair.getExtendedPublicKey();
    }

    @BeforeEach
    void setUp() {
        randomness = BigInteger.TEN;

        R_0 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(58));
        R_1 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(29));
        R_2 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(79));


        m_0 = BigInteger.valueOf(44);
        m_1 = BigInteger.valueOf(89);
        m_2 = BigInteger.valueOf(59);

        BaseRepresentation base_0 = new BaseRepresentation(R_0, 0, BASE.ALL);
        BaseRepresentation base_1 = new BaseRepresentation(R_1, 1, BASE.ALL);
        BaseRepresentation base_2 = new BaseRepresentation(R_2, 2, BASE.ALL);

        base_0.setExponent(m_0);
        base_1.setExponent(m_1);
        base_2.setExponent(m_2);

        baseCollection = new BaseCollectionImpl();
        baseCollection.add(base_0);
        baseCollection.add(base_1);
        baseCollection.add(base_2);

        commitment = GSCommitment.createCommitment(baseCollection, randomness, epk);
    }

    @Test
    @DisplayName("Test computing a commitment with multiple bases and exponents with extended public key")
    void testcomputeCommitmentMultiBase() {

        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(R_1.modPow(m_1)).multiply(R_2.modPow(m_2)).multiply(epk.getPublicKey().getBaseS().modPow(commitment.getRandomness()));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test computing a commitment with multiple bases and exponents with extended public key")
    void testcomputeCommitmentMultiBaseRep() {
        BaseRepresentation baseRep_0 = new BaseRepresentation(R_0, 0, BaseRepresentation.BASE.BASE0);
        baseRep_0.setExponent(m_0);
        BaseRepresentation baseRep_1 = new BaseRepresentation(R_1, 1, BaseRepresentation.BASE.EDGE);
        baseRep_1.setExponent(m_1);
        BaseRepresentation baseRep_2 = new BaseRepresentation(R_2, 2, BaseRepresentation.BASE.VERTEX);
        baseRep_2.setExponent(m_2);

        BaseCollection newCollection = new BaseCollectionImpl();
        newCollection.add(baseRep_0);
        newCollection.add(baseRep_1);
        newCollection.add(baseRep_2);

        GSCommitment commitment = GSCommitment.createCommitment(newCollection, randomness, epk);
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(R_1.modPow(m_1)).multiply(R_2.modPow(m_2)).multiply(epk.getPublicKey().getBaseS().modPow(commitment.getRandomness()));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test computing a commitment with one base and exponent when using modN and base S")
    void testcomputeCommitment() {
        GSCommitment commitment = GSCommitment.createCommitment(R_0, m_0, randomness, epk.getPublicKey().getBaseS(), epk.getPublicKey().getModN());
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(randomness));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test computing a commitment with  base and exponent when using EPK")
    void testcomputeCommitmentWithEPK() {
        GSCommitment commitment = GSCommitment.createCommitment(m_0, R_0, epk);
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(commitment.getRandomness()));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test computing a commitment with R base representation when using EPK")
    void testcomputeCommitmentWithBaseRep() {
        BaseRepresentation baseRepresentation = new BaseRepresentation(epk.getPublicKey().getBaseR(), 0, BaseRepresentation.BASE.BASE0);
        baseRepresentation.setExponent(m_0);

        BaseCollection collection = new BaseCollectionImpl();
        collection.add(baseRepresentation);

        GSCommitment commitment = GSCommitment.createCommitment(collection, randomness, epk);
        assertNotNull(commitment);
        GroupElement baseR = epk.getPublicKey().getBaseR();
        GroupElement result = baseR.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(commitment.getRandomness()));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test returning commitment value")
    void getCommitmentValue() {
        GroupElement commitmentValue = commitment.getCommitmentValue();
        assertNotNull(commitmentValue);

    }

    @Test
    @DisplayName("Test returning map of bases")
    void getBaseCollection() {
        BaseCollection bases = commitment.getBaseCollection();
        assertNotNull(bases);
        assertTrue(bases.size() > 0);
    }


    @Test
    @DisplayName("Test returning randomness")
    void getRandomness() {
        GSCommitment commitment = GSCommitment.createCommitment(R_0, m_0, randomness, epk.getPublicKey().getBaseS(), epk.getPublicKey().getModN());
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(randomness));
        assertEquals(result, commitment.getCommitmentValue());
        BigInteger rand = commitment.getRandomness();
        assertNotNull(rand);
        assertEquals(BigInteger.TEN, rand);
    }
}