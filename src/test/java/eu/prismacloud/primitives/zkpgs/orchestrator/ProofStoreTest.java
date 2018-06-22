package eu.prismacloud.primitives.zkpgs.orchestrator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class ProofStoreTest {
  ProofStore<Object> proverStore;

  @BeforeEach
  void setUp() {
    proverStore = new ProofStore<>(10);
  }

  @Test
  void put() throws Exception {

    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "biginteger.2"), BigInteger.valueOf(1));
    List<GSCommitment> commitments = new ArrayList<GSCommitment>();
    commitments.add(
        new GSCommitment(
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.TEN,
            new QRElementN(BigInteger.ONE).getValue(),
            BigInteger.ONE));
    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "commitments.ci"), commitments);

    assertEquals(2, proverStore.size());
  }

  @Test
  void storeSameElement() throws Exception {

    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "biginteger.2"), BigInteger.valueOf(1));
    List<GSCommitment> commitments = new ArrayList<GSCommitment>();
    commitments.add(
        new GSCommitment(
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.TEN,
            new QRElementN(BigInteger.ONE).getValue(),
            BigInteger.ONE));
    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "commitments.ci"), commitments);

    Throwable exception =
        assertThrows(
            Exception.class,
            () -> {
              proverStore.store(
                  URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "biginteger.2"),
                  BigInteger.valueOf(2));
            });

    assertThat(
        exception.getMessage(), CoreMatchers.containsString("with type URN was already added"));

    assertEquals(2, proverStore.size());
  }

  @Test
  void retrieve() throws Exception {

    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "biginteger.2"), BigInteger.valueOf(1));
    List<GSCommitment> commitments = new ArrayList<GSCommitment>();
    commitments.add(
        new GSCommitment(
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.TEN,
            new QRElementN(BigInteger.ONE).getValue(),
            BigInteger.ONE));
    proverStore.store(
        URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "commitments.ci"), commitments);

    //       proverStore.store(URN.createURN(URN.getZkpgsNameSpaceIdentifier(),"biginteger.2" ),
    // BigInteger.valueOf(2));
    //       proverStore.store(URN.createURN(URN.getZkpgsNameSpaceIdentifier(),"biginteger.2" ),
    // BigInteger.valueOf(3));

    BigInteger el =
        (BigInteger)
            proverStore.retrieve(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "biginteger.2"));
    assertNotNull(el);
  }

  @Test
  void add() {}

  @Test
  void remove() {}

  @Test
  void isEmpty() {}

  @Test
  void getElements() {}
}
