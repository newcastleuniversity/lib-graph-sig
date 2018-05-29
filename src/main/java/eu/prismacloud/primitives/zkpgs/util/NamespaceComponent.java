package eu.prismacloud.primitives.zkpgs.util;

import java.util.regex.Pattern;

/**
 * A NamespaceComponent represents either a Namespace Identifier or a Namespace Specific String
 *
 * @see <a href="https://tools.ietf.org/html/rfc2141">URN Syntax</a>
 * @see <a href="https://tools.ietf.org/html/rfc1737">Functional Requirements for Uniform Resource
 *     Names</a>
 */
public class NamespaceComponent {
  private String content;
  /** regular expression for namespace identifier */
  private static Pattern nidPattern = Pattern.compile("^[0-9a-zA-Z]+[0-9a-zA-Z-]{0,31}$");
  /** regular expression for namespace specific string */
  private static Pattern nssPattern =
      Pattern.compile("^([0-9a-zA-Z()+,-.:=@;$_!*']|(%[0-9a-fA-F]{2}))+$");

  /** The enum Type. */
  public enum Type {
    /** Namespace Identifier */
    IDENTIFIER,
    /** Namespace Specific string */
    SPECIFIC_STRING
  }

  private NamespaceComponent(final String textContent) {
    this.content = textContent;
  }

  /**
   * Create a namespace component object from string input.
   *
   * @param textContent the text content
   * @param ncType the nc type
   * @return the namespace component
   * @pre textContent != null && textContent != ""
   * @post
   */
  public static NamespaceComponent fromString(final String textContent, final Type ncType) {
    Assert.notNull(textContent, "NamespaceComponent cannot be null in a urn");
    Assert.notEmpty(textContent, "NamespaceComponent cannot be empty in a urn");
    validate(textContent, ncType);
    return new NamespaceComponent(textContent);
  }

  /**
   * Validate.
   *
   * @param nc the nc
   * @param ncType the nc type
   */
  public static void validate(final String nc, final Type ncType) {
    if (ncType == Type.IDENTIFIER) {
      validateNID(nc);
    } else {
      validateNSS(nc);
    }
  }

  private static void validateNID(final String nid) {
    if (!nidPattern.matcher(nid).matches()) {
      throw new IllegalArgumentException("Characters not allowed found in Namespace Identifier");
    }
  }

  private static void validateNSS(final String nss) {
    if (!nssPattern.matcher(nss).matches()) {
      throw new IllegalArgumentException(
          "Characters not allowed found in Namespace Specific String");
    }
  }
}
