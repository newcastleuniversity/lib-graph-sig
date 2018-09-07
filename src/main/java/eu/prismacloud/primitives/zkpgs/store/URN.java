package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.NamespaceComponent;
import eu.prismacloud.primitives.zkpgs.util.NamespaceComponent.Type;
import java.io.Serializable;
import java.util.StringTokenizer;

/**
 * Class represents a Uniform Resource Name (URN)
 *
 * @see <a href="https://tools.ietf.org/html/rfc2141">URN Syntax</a>
 * @see <a href="https://tools.ietf.org/html/rfc1737">Functional Requirements for Uniform Resource
 *     Names</a>
 */
public final class URN implements Serializable {

	private static final String zkpgsNameSpaceIdentifier = "zkpgs";
	private static final String URN_SCHEME = "urn";
	public static final String COLON = ":";
	public static final String DOT = ".";
	private static final long serialVersionUID = -3082747487978142725L;
	private final NamespaceComponent namespaceIdentifier;
	private final NamespaceComponent namespaceSpecific;

	private URN(
			final NamespaceComponent namespaceIdentifier, final NamespaceComponent namespaceSpecific) {

		this.namespaceIdentifier = namespaceIdentifier;
		this.namespaceSpecific = namespaceSpecific;
	}

	/**
	 * Gets zkpgs name space identifier.
	 *
	 * @return the zkpgs name space identifier
	 */
	public static String getZkpgsNameSpaceIdentifier() {
		return zkpgsNameSpaceIdentifier;
	}
	/**
	 * Create urn from namespaceIdentifier and namespaceSpecific from NamespaceComponent objects.
	 *
	 * @param namespaceIdentifier the namespace identifier
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceSpecific != null \)
	 * @post
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
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceIdentifier != "" \and namespaceSpecific != null \and
	 *     namespaceSpecific != "" \)
	 * @post
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

	/**
	 * Helper method to create a zkpgs based urn.
	 *
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 */
	public static URN createZkpgsURN(final String namespaceSpecific) {
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");
		Assert.notEmpty(namespaceSpecific, "Namespace Specific String must not be empty in a urn");

		NamespaceComponent nic =
				NamespaceComponent.fromString(URN.getZkpgsNameSpaceIdentifier(), Type.IDENTIFIER);
		NamespaceComponent nssc =
				NamespaceComponent.fromString(namespaceSpecific, Type.SPECIFIC_STRING);

		return new URN(nic, nssc);
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("URN{");
		sb.append("zkpgsNameSpaceIdentifier='").append(zkpgsNameSpaceIdentifier).append('\'');
		sb.append(", URN_SCHEME='").append(URN_SCHEME).append('\'');
		sb.append(", COLON='").append(COLON).append('\'');
		sb.append(", namespaceIdentifier=").append(namespaceIdentifier);
		sb.append(", namespaceSpecific=").append(namespaceSpecific);
		sb.append('}');
		return sb.toString();
	}

	public String toHumanReadableString() {
		final StringBuilder sb = new StringBuilder("URN:");
		sb.append(namespaceSpecific.getContent());
		return sb.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || this.getClass() != o.getClass()) {
			return false;
		}

		URN urn = (URN) o;

		if (!this.namespaceIdentifier.equals(urn.namespaceIdentifier)) {
			return false;
		}
		return this.namespaceSpecific.equals(urn.namespaceSpecific);
	}

	@Override
	public int hashCode() {
		int result = this.namespaceIdentifier.hashCode();
		result = 31 * result + this.namespaceSpecific.hashCode();
		return result;
	}

	/**
	 * Checks whether the namespace-specifc component starts with a String prefix.
	 * 
	 * @param prefix String prefix the namespace-specific component must start with.
	 * 
	 * @return <tt>true</tt> if and only if the namespace-specific component of this URN
	 * starts with the given prefix.
	 */
	public boolean matchesPrefix(String prefix) {
		return namespaceSpecific.getContent().startsWith(prefix);
	}

	/**
	 * Returns the index of an enumerated URN. 
	 * It returns -1 if this URN does not have an index.
	 * 
	 * @return index
	 */
	public int getIndex() {
		StringTokenizer tokenizer = new StringTokenizer(namespaceSpecific.getContent(), ".");
		while (tokenizer.hasMoreTokens()) {
			String token = (String) tokenizer.nextToken();

			if (!tokenizer.hasMoreTokens()) {
				try {
					int index = Integer.parseInt(token);
					return index;
				} catch (NumberFormatException e) {
					return -1;
				}
			}
		}
		return -1;
	}
}
