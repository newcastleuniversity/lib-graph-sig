package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.util.NamespaceComponent.Type;

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
  private final NamespaceComponent namespaceIdentifier;
  private final NamespaceComponent namespaceSpecific;

  private URN(
      final NamespaceComponent namespaceIdentifier, final NamespaceComponent namespaceSpecific) {

    this.namespaceIdentifier = namespaceIdentifier;
    this.namespaceSpecific = namespaceSpecific;
  }

  /**
   * Create urn from namespaceIdentifier and namespaceSpecific from NamespaceComponent objects.
   *
   * @param namespaceIdentifier the namespace identifier
   * @param namespaceSpecific the namespace specific
   * @pre namespaceIdentifier != null && namespaceSpecific != null
   * @post
   * @return the urn
   */
  public static URN createURN(
      final NamespaceComponent namespaceIdentifier, final NamespaceComponent namespaceSpecific) {

    Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
    Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");

    return new URN(namespaceIdentifier, namespaceSpecific);
  }

  /**
   * Create urn from namespaceIdentifier and namespaceSpecific strings.
   *
   * @param namespaceIdentifier the namespace identifier
   * @param namespaceSpecific the namespace specific
   * @pre namespaceIdentifier != null && namespaceIdentifier != "" && namespaceSpecific != null &&
   *     namespaceSpecific != ""
   * @post
   * @return the urn
   */
  public static URN createURN(final String namespaceIdentifier, final String namespaceSpecific) {

    Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
    Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");
    Assert.notEmpty(namespaceIdentifier, "Namespace Identifier must not be empty in a urn");
    Assert.notEmpty(namespaceSpecific, "Namespace Specific String must not be empty in a urn");

    NamespaceComponent nic = NamespaceComponent.fromString(namespaceIdentifier, Type.IDENTIFIER);
    NamespaceComponent nssc =
        NamespaceComponent.fromString(namespaceSpecific, Type.SPECIFIC_STRING);

    return new URN(nic, nssc);
  }
}
