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
	private final URNClass urnClass;
	private final URNType urnType;

	private URN(
			final NamespaceComponent namespaceIdentifier, 
			final NamespaceComponent namespaceSpecific, boolean enforceUntyped) {

		this.namespaceIdentifier = namespaceIdentifier;
		this.namespaceSpecific = namespaceSpecific;

		if (enforceUntyped) {
			this.urnType = URNType.UNDEFINED;
			this.urnClass = URNClass.UNDEFINED;
		} else {
			this.urnType = URNType.parseURNType(namespaceSpecific.getContent());
			this.urnClass = URNType.getClass(this.urnType);
		}
	}

	private URN(
			final NamespaceComponent namespaceIdentifier, 
			final NamespaceComponent namespaceSpecific,
			final URNType urnType) {

		Assert.notNull(namespaceIdentifier, "The namespace of an URN must not be null.");
		Assert.notNull(namespaceSpecific, "The namespace-specific part of an URN must not be null.");
		Assert.notNull(urnType, "The URNType must not be null.");
		this.namespaceIdentifier = namespaceIdentifier;
		this.namespaceSpecific = namespaceSpecific;
		
		if (!URNType.isTypeValid(urnType, URN.parseSuffix(namespaceSpecific.getContent()))) {
			throw new RuntimeException("The named URNType is not valid for the given namespace-specific component.");
		}
		
		this.urnType = urnType;
		this.urnClass = URNType.getClass(urnType);
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
	 * Creates an URN from namespaceIdentifier and namespaceSpecific NamespaceComponent objects.
	 * The URNType is inferred and a RuntimeException thrown if the URNType cannot be determined.
	 *
	 * @param namespaceIdentifier the namespace identifier
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceSpecific != null \)
	 * @post
	 */
	public static URN createURN(
			final NamespaceComponent namespaceIdentifier, 
			final NamespaceComponent namespaceSpecific) {

		Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");

		return new URN(namespaceIdentifier, namespaceSpecific, false);
	}
	

	/**
	 * Create an URN from namespaceIdentifier and namespaceSpecific from 
	 * NamespaceComponent objects with a designated URNType.
	 *
	 * @param namespaceIdentifier the namespace identifier
	 * @param namespaceSpecific the namespace specific
	 * @param urnType designated type of the URN.
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceSpecific != null \)
	 * @post
	 */
	public static URN createURN(
			final NamespaceComponent namespaceIdentifier, 
			final NamespaceComponent namespaceSpecific,
			final URNType urnType) {

		Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");
		Assert.notNull(urnType, "The URNType was null.");

		return new URN(namespaceIdentifier, namespaceSpecific, urnType);
	}

	/**
	 * Creates an URN from namespaceIdentifier and namespaceSpecific from NamespaceComponent objects
	 * while deactivating the URNType protection. The URNType and URNClass will be set
	 * to UNDEFINED.
	 *
	 * @param namespaceIdentifier the namespace identifier
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceSpecific != null \)
	 * @post
	 */
	public static URN createUnsafeURN(
			final NamespaceComponent namespaceIdentifier, final NamespaceComponent namespaceSpecific) {

		Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");

		return new URN(namespaceIdentifier, namespaceSpecific, true);
	}

	/**
	 * Creates an URN from namespaceIdentifier and namespaceSpecific from NamespaceComponent objects
	 * while deactivating the URNType protection. The URNType and URNClass will be inferred from
	 * the suffix of the namespace-specific namespace component and a RuntimeException thrown should
	 * the URNType not be determinable.
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

		return new URN(nic, nssc, false);
	}

	/**
	 * Helper method to create a zkpgs based URN from a namespace-specific String.
	 * The URNType will be inferred from the namespace-specific component and a runtime 
	 * exception thrown if the URNType cannot be determined.
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

		return new URN(nic, nssc, false);
	}

	/**
	 * Creates an URN from namespaceIdentifier and namespaceSpecific Strings
	 * while deactivating the URNType protection. The URNType and URNClass will be set
	 * to UNDEFINED.
	 *
	 * @param namespaceIdentifier the namespace identifier
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 * @pre \( namespaceIdentifier != null \and namespaceIdentifier != "" \and namespaceSpecific != null \and
	 *     namespaceSpecific != "" \)
	 * @post
	 */
	public static URN createUnsafeURN(final String namespaceIdentifier, final String namespaceSpecific) {

		Assert.notNull(namespaceIdentifier, "Namespace Identifier is required for URN");
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");
		Assert.notEmpty(namespaceIdentifier, "Namespace Identifier must not be empty in a urn");
		Assert.notEmpty(namespaceSpecific, "Namespace Specific String must not be empty in a urn");

		NamespaceComponent nic = NamespaceComponent.fromString(namespaceIdentifier, Type.IDENTIFIER);
		NamespaceComponent nssc =
				NamespaceComponent.fromString(namespaceSpecific, Type.SPECIFIC_STRING);

		return new URN(nic, nssc, true);
	}

	/**
	 * Helper method to create a zkpgs based URN,  while deactivating the URNType protection.
	 * The URNType and URNClass will be set to UNDEFINED.
	 *
	 * @param namespaceSpecific the namespace specific
	 * @return the urn
	 */
	public static URN createUnsafeZkpgsURN(final String namespaceSpecific) {
		Assert.notNull(namespaceSpecific, "Namespace Specific String is required for URN");
		Assert.notEmpty(namespaceSpecific, "Namespace Specific String must not be empty in a urn");

		NamespaceComponent nic =
				NamespaceComponent.fromString(URN.getZkpgsNameSpaceIdentifier(), Type.IDENTIFIER);
		NamespaceComponent nssc =
				NamespaceComponent.fromString(namespaceSpecific, Type.SPECIFIC_STRING);

		return new URN(nic, nssc, true);
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
	 * Returns the suffix of an URN. 
	 * It returns null if the URN namespace-specific component is empty.
	 * 
	 * @return suffix
	 */
	public String getSuffix() {
		return URN.parseSuffix(this.namespaceSpecific.getContent());
	}

	/**
	 * Returns the index of an enumerated URN. 
	 * It returns -1 if this URN does not have an index.
	 * 
	 * @return index
	 */
	public int getIndex() {
		return URN.parseIndex(this.getSuffix());
	}

	protected static String parseSuffix(String urnString) {
		StringTokenizer tokenizer = new StringTokenizer(urnString, ".");
		String token = null;
		while (tokenizer.hasMoreTokens()) {
			token = (String) tokenizer.nextToken();

			if (!tokenizer.hasMoreTokens()) {
				return token;
			}
		}
		return token;
	}

	protected static int parseIndex(String urnString) {
		String suffix = URN.parseSuffix(urnString);
		StringTokenizer tokenizer = new StringTokenizer(suffix, "_");
		while (tokenizer.hasMoreTokens()) {
			String token = (String) tokenizer.nextToken();
			try {
				int index = Integer.parseInt(token);
				return index;
			} catch (NumberFormatException e) {
				return -1;
			}
		}
		return -1;
	}

	public URNClass getURNClass() {
		return urnClass;
	}

	public URNType getURNType() {
		return urnType;
	}
}
