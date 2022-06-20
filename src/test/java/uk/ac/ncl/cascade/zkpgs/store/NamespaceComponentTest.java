package uk.ac.ncl.cascade.zkpgs.store;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import uk.ac.ncl.cascade.zkpgs.util.NamespaceComponent;
import uk.ac.ncl.cascade.zkpgs.util.NamespaceComponent.Type;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class NamespaceComponentTest {

  String urn = "baseRepresentationMap.vertex.R_i_1";
  NamespaceComponent nsc;

  @BeforeEach
  void setUp() {}

  @Test
  void fromString() {
    nsc = NamespaceComponent.fromString(urn, Type.SPECIFIC_STRING);
    assertNotNull(nsc);
  }

  @Test
  void validate() {
    NamespaceComponent.validate(urn, Type.SPECIFIC_STRING);
  }
}
