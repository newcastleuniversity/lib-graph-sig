package uk.ac.ncl.cascade.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertNull;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollectionImpl;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupN;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BaseServiceTest {
  private BaseCollectionImpl ba;
  private BaseIterator it;
  private QRElementN R_1;
  private QRGroupN qrGroup;
  private QRElementN R_0;
  private QRElementN R_2;
  private QRElementN R_3;
  private QRElementN R_4;
  private QRElementN R_5;
  private QRElementN R_6;
  private QRElementN R_7;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  @BeforeEach
  void setUp() {
    ba = new BaseCollectionImpl();
    it = ba.createIterator(BASE.ALL);
    qrGroup = new QRGroupN(BigInteger.valueOf(77));
    R_0 = new QRElementN(qrGroup, BigInteger.valueOf(58));
    R_1 = new QRElementN(qrGroup, BigInteger.valueOf(15));
    R_2 = new QRElementN(qrGroup, BigInteger.valueOf(23));
    R_3 = new QRElementN(qrGroup, BigInteger.valueOf(43));
    R_4 = new QRElementN(qrGroup, BigInteger.valueOf(49));
    R_5 = new QRElementN(qrGroup, BigInteger.valueOf(53));
    R_6 = new QRElementN(qrGroup, BigInteger.valueOf(39));
    R_7 = new QRElementN(qrGroup, BigInteger.valueOf(18));
  }

  @AfterEach
  void tearDown() {
    ba = null;
    it = null;
  }

  @Test
  void TestIteratorNotNull() {
    assertNotNull(it);
  }

  @Test
  void testNotEmpty() {
    assertFalse(it.hasNext());
  }

  @Test
  @DisplayName(
      "Test the size of the BaseRepresentationCollection when adding new BaseRepresentations")
  void testBaseCollectionSize() {
    ba.add(new BaseRepresentation(R_0, BigInteger.valueOf(541), 0, BASE.BASE0));
    ba.add(new BaseRepresentation(R_1, BigInteger.valueOf(113), 1, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_2, BigInteger.valueOf(179), 2, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_3, BigInteger.valueOf(163), 3, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_4, BigInteger.valueOf(41), 4, BASE.EDGE));
    ba.add(new BaseRepresentation(R_5, BigInteger.valueOf(89), 5, BASE.EDGE));
    ba.add(new BaseRepresentation(R_6, BigInteger.valueOf(109), 6, BASE.EDGE));
    ba.add(new BaseRepresentation(R_7, BigInteger.valueOf(509), 7, BASE.EDGE));
    assertEquals(8, ba.size());
  }

  @Test
  @DisplayName("Test base collection when returning only a certain type of bases")
  void testBaseCollectionByType() {
    ba.add(new BaseRepresentation(R_0, BigInteger.valueOf(541), 0, BASE.BASE0));
    ba.add(new BaseRepresentation(R_1, BigInteger.valueOf(113), 1, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_2, BigInteger.valueOf(179), 2, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_3, BigInteger.valueOf(163), 3, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_4, BigInteger.valueOf(41), 4, BASE.EDGE));
    ba.add(new BaseRepresentation(R_5, BigInteger.valueOf(89), 5, BASE.EDGE));
    ba.add(new BaseRepresentation(R_6, BigInteger.valueOf(109), 6, BASE.EDGE));
    ba.add(new BaseRepresentation(R_7, BigInteger.valueOf(509), 7, BASE.EDGE));
    // filter by vertex
    BaseIterator vertexIterator = ba.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      gslog.info("base index: " + baseRepresentation.getBaseIndex());
      gslog.info("base type: " + baseRepresentation.getBaseType());
      assertEquals(BASE.VERTEX, baseRepresentation.getBaseType());
    }

    BaseIterator edgeIterator = ba.createIterator(BASE.EDGE);

    for (BaseRepresentation baseRepresentation : edgeIterator) {
      gslog.info("base index: " + baseRepresentation.getBaseIndex());
      gslog.info("base type: " + baseRepresentation.getBaseType());
      assertEquals(BASE.EDGE, baseRepresentation.getBaseType());
    }
  }

  @Test
  @DisplayName("Test base collection when returning all types of bases")
  void testBaseCollectionAll() {
    ba.add(new BaseRepresentation(R_0, BigInteger.valueOf(541), 0, BASE.BASE0));
    ba.add(new BaseRepresentation(R_1, BigInteger.valueOf(113), 1, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_2, BigInteger.valueOf(179), 2, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_3, BigInteger.valueOf(163), 3, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_4, BigInteger.valueOf(41), 4, BASE.EDGE));
    ba.add(new BaseRepresentation(R_5, BigInteger.valueOf(89), 5, BASE.EDGE));
    ba.add(new BaseRepresentation(R_6, BigInteger.valueOf(109), 6, BASE.EDGE));
    ba.add(new BaseRepresentation(R_7, BigInteger.valueOf(509), 7, BASE.EDGE));
    // return all bases
    BaseIterator iterator = ba.createIterator(BASE.ALL);
    int i = 0;
    for (BaseRepresentation baseRepresentation : iterator) {
      gslog.info("base index: " + baseRepresentation.getBaseIndex());
      gslog.info("base type: " + baseRepresentation.getBaseType());
      assertNotNull(baseRepresentation);
      i++;
    }
    gslog.info("i: " + i);
    assertEquals(8, i);
  }

  @Test
  void testTraversalWithoutHasNext() {
    BaseRepresentation b = new BaseRepresentation(R_1, BigInteger.valueOf(3234), 1, BASE.VERTEX);
    ba.add(b);
    assertSame(b, it.next());
    assertFalse(it.hasNext());
  }

  @Test
  void testNullElements() {
    BaseRepresentation b = new BaseRepresentation(R_1, BigInteger.valueOf(3234), 1, BASE.VERTEX);
    BaseRepresentation ban = null;
    ba.add(b);
    ba.add(ban);
    assertSame(b, it.next());
    assertNull(it.next());
    assertFalse(it.hasNext());
  }

  @Test
  void testCountIterator() {
    BaseRepresentation b = new BaseRepresentation(R_1, BigInteger.valueOf(3234), 1, BASE.VERTEX);
    BaseRepresentation c = new BaseRepresentation(R_1, BigInteger.valueOf(3234), 1, BASE.VERTEX);
    ba.add(b);
    ba.add(c);
    int counter = 0;

    while (it.hasNext()) {
      ++counter;
      it.next();
    }
    assertEquals(ba.size(), counter);
  }

  @Test
  void getBases() {
    ba.add(new BaseRepresentation(R_0, BigInteger.valueOf(541), 0, BASE.BASE0));
    ba.add(new BaseRepresentation(R_1, BigInteger.valueOf(113), 1, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_2, BigInteger.valueOf(179), 2, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_3, BigInteger.valueOf(163), 3, BASE.VERTEX));
    ba.add(new BaseRepresentation(R_4, BigInteger.valueOf(41), 4, BASE.EDGE));
    ba.add(new BaseRepresentation(R_5, BigInteger.valueOf(89), 5, BASE.EDGE));
    ba.add(new BaseRepresentation(R_6, BigInteger.valueOf(109), 6, BASE.EDGE));
    ba.add(new BaseRepresentation(R_7, BigInteger.valueOf(509), 7, BASE.EDGE));
    assertNotNull(ba.getBases());
    assertEquals(8, ba.getBases().size());
  }

  @Test
  void get() {
    ba.add(new BaseRepresentation(R_0, BigInteger.valueOf(541), 0, BASE.BASE0));
    BaseRepresentation baseRepresentation = ba.get(0);
    assertNotNull(baseRepresentation);
    assertEquals(R_0, baseRepresentation.getBase());
    assertEquals(BigInteger.valueOf(541), baseRepresentation.getExponent());
    assertEquals(0, baseRepresentation.getBaseIndex());
    assertEquals(BASE.BASE0, baseRepresentation.getBaseType());
  }
}
