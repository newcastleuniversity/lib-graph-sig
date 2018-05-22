package eu.prismacloud.primitives.grs.utils;

import java.net.URI;

/**
 * Class represents a Uniform Resource Name (URN)
 *
 * @see <a href="https://tools.ietf.org/html/rfc2141">URN Syntax</a>
 * @see <a href="https://tools.ietf.org/html/rfc1737">Functional Requirements for Uniform Resource
 *     Names</a>
 */
public final class URN {

  private static final String URN_SCHEME = "urn";
  private static final String COLON = ":";
  private final String namespaceIdentifier;
  private final String namespaceSpecific;

  private URN(String namespaceIdentifier, String namespaceSpecific) {

    this.namespaceIdentifier = namespaceIdentifier;
    this.namespaceSpecific = namespaceSpecific;
  }

  /**
   * Create urn from namespaceIdentifier and namespaceSpecific string.
   *
   * @param namespaceIdentifier the namespace identifier
   * @param namespaceSpecific the namespace specific
   * @return the urn
   * @throws Exception the exception
   */
  public static URN createURN(String namespaceIdentifier, String namespaceSpecific)
      throws Exception {

    try {
      return new URN(namespaceIdentifier, namespaceSpecific);
    } catch (IllegalArgumentException e) {
      throw new Exception(" Error creating URN", e);
    }
  }

  /**
   * Create a urn from a uri.
   *
   * @param uri the uri
   * @return the urn
   * @throws Exception the exception
   */
  public static URN fromURI(URI uri) throws Exception {
    final String uriScheme = uri.getScheme();

    if (!URN_SCHEME.equalsIgnoreCase(uriScheme)) {
      throw new IllegalArgumentException("Invalid scheme ");
    }

    final String specificPart = uri.getSchemeSpecificPart();
    int colonPosition = specificPart.indexOf(COLON);

    if (colonPosition > -1) {
      return new URN(
          specificPart.substring(0, colonPosition), specificPart.substring(colonPosition + 1));

    } else {
      throw new IllegalArgumentException("invalid format for a URN part");
    }
  }
}
