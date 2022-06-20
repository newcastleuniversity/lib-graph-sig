package uk.ac.ncl.cascade.zkpgs.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.NamespaceComponent;
import uk.ac.ncl.cascade.zkpgs.util.NamespaceComponent.Type;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class URNTest {

  @Test
  void createURN() {
    NamespaceComponent ns = NamespaceComponent.fromString("ns", Type.IDENTIFIER);

    NamespaceComponent nss = NamespaceComponent.fromString("test.ns.tildeA", Type.SPECIFIC_STRING);
    URN testURN = URN.createURN(ns, nss);
    assertNotNull(testURN);
  }

  @Test
  @DisplayName("Test creating URN from a string")
  void testCreateURNWithString() {
    URN testURN = URN.createURN("ns", "test.tildeA");
    assertNotNull(testURN);
  }

  @Test
  void getZkpgsNameSpaceIdentifier() {
    URN testURN = URN.createZkpgsURN("test.ns.tildeA");
    assertEquals("zkpgs", URN.getZkpgsNameSpaceIdentifier());
  }

  @Test
  void createZkpgsURN() {
    URN testURN = URN.createZkpgsURN("test.ns.tildeA");
    assertNotNull(testURN);
  }
}
