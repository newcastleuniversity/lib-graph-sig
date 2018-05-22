package eu.prismacloud.primitives.grs.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;

import eu.prismacloud.primitives.grs.store.Base;
import eu.prismacloud.primitives.grs.util.BaseIterator;
import eu.prismacloud.primitives.grs.util.BaseService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BaseServiceTest {
  private BaseService ba;
  private BaseIterator it;

  @BeforeEach
  void setUp() {
    ba = new BaseService();
    it = ba.createIterator();
  }

  @AfterEach
  void tearDown() {}

  @Test
  void getIterator() {}

  @Test
  void testEmpty() {
    assertFalse(it.hasNext());
  }

  @Test
  void testSingletonList() {
    ba.add(new Base("R_0", "1"));
    ba.add(new Base("R_1", "2"));
    ba.add(new Base("R_2", "3"));
    assertEquals(3, ba.size());
    assertTrue(it.hasNext());
    it.next();
    it.next();
    it.next();
    assertFalse(it.hasNext());
  }

  @Test
  void testTraversalWithoutHasNext() {
    Base b = new Base("R_0", "1");
    ba.add(b);
    assertSame(b, it.next());
    assertFalse(it.hasNext());
  }

  @Test
  void testNullElements() {
    Base b = new Base("R_0", "1");
    Base ban = null;
    ba.add(b);
    ba.add(ban);
    assertSame(b, it.next());
    assertNull(it.next());
    assertFalse(it.hasNext());
  }

  @Test
  void testCountIterator() {
    Base b = new Base("R_0", "1");
    Base c = new Base("R_1", "2");
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
  void getBases() {}

  @Test
  void setBases() {}

  @Test
  void get() {}

  @Test
  void size() {}
}
