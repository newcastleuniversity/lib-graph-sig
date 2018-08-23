package eu.prismacloud.primitives.zkpgs.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupN;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** */
class ProofStoreTest {
  ProofStore<Object> proofStore;
  QRGroup testGroup;
  GroupElement testS;
  GroupElement testR;

  @BeforeEach
  void setUp() {
    proofStore = new ProofStore<Object>(10);
    testGroup = new QRGroupN(BigInteger.valueOf(77));
    testS = new QRElementN(testGroup, BigInteger.valueOf(60));
    testR = new QRElementN(testGroup, BigInteger.valueOf(58));
  }

  @Test
  @DisplayName("Test add a new object in the proof store")
  void put() throws Exception {

    proofStore.store("biginteger.2", BigInteger.valueOf(1));
    BigInteger testM = CryptoUtilsFacade.computeRandomNumber(1024);
    proofStore.store("test.M", testM);
    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test throwing an exception when adding the same object in the proof store")
  void storeSameElement() throws Exception {

    proofStore.store("biginteger.2", BigInteger.valueOf(1));
    GSCommitment gsCommitment =
        new GSCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.store("commitments.ci", gsCommitment);

    Throwable exception =
        assertThrows(
            Exception.class,
            () -> {
              proofStore.store("biginteger.2", BigInteger.valueOf(2));
            });

    String exceptionMessage = exception.getMessage();
    Boolean containsString = exceptionMessage.contains("with type URN was already added");
    assertTrue(containsString);

    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test retrieve an object from the store")
  void retrieve() throws Exception {

    proofStore.store("biginteger.2", BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        new GSCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.store("commitments.ci", gsCommitment);

    BigInteger el = (BigInteger) proofStore.retrieve("biginteger.2");
    assertNotNull(el);
  }

  @Test
  @DisplayName("Test proof store for adding objects")
  void add() throws ProofStoreException {

    proofStore.add(URN.createZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        new GSCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.store("commitments.ci", gsCommitment);

    BigInteger el = (BigInteger) proofStore.retrieve("biginteger.2");
    assertNotNull(el);
    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test proof store for removing objects")
  void remove() throws ProofStoreException {
    proofStore.add(URN.createZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        new GSCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.store("commitments.ci", gsCommitment);

    proofStore.remove(URN.createZkpgsURN("biginteger.2"));

    assertEquals(1, proofStore.size());
  }

  @Test
  @DisplayName("Test proof store for outputting that the it is empty")
  void isEmpty() throws ProofStoreException {
    proofStore.add(URN.createZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    assertEquals(1, proofStore.size());

    proofStore.remove(URN.createZkpgsURN("biginteger.2"));

    assertTrue(proofStore.isEmpty());
  }

  @Test
  @DisplayName("Test proof store getElement for correct collection size")
  void getElements() throws ProofStoreException {
    proofStore.add(URN.createZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        new GSCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.store("commitments.ci", gsCommitment);

    assertNotNull(proofStore.getElements());
    assertEquals(2, proofStore.getElements().size());
  }
}
