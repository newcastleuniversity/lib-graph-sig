package eu.prismacloud.primitives.zkpgs.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import eu.prismacloud.primitives.zkpgs.util.NamespaceComponent.Type;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class URNTest {

  @Test
  void createURN() {
    NamespaceComponent ns = NamespaceComponent.fromString("ns", Type.IDENTIFIER);

    NamespaceComponent nss = NamespaceComponent.fromString("test.ns", Type.SPECIFIC_STRING);
    URN testURN = URN.createURN(ns, nss);
    assertNotNull(testURN);
  }

  @Test
  @DisplayName("Test creating URN from a string")
  void testCreateURNWithString() {
    URN testURN = URN.createURN("ns", "test.ns");
    assertNotNull(testURN);
  }

  @Test
  void getZkpgsNameSpaceIdentifier() {
    URN testURN = URN.createZkpgsURN("test.ns");
    assertEquals("zkpgs", URN.getZkpgsNameSpaceIdentifier());
  }

  @Test
  void createZkpgsURN() {
    URN testURN = URN.createZkpgsURN("test.ns");
    assertNotNull(testURN);
  }
}
