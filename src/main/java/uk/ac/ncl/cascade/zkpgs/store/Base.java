package uk.ac.ncl.cascade.zkpgs.store;
/** Base class for edge and vertex identifiers for bases. */
public class Base {
  private String baseName;
  private String baseId;

  public Base(String baseName, String baseId) {
    this.baseName = baseName;
    this.baseId = baseId;
  }

  public String getBaseName() {
    return this.baseName;
  }

  public String getBaseId() {
    return this.baseId;
  }
}
