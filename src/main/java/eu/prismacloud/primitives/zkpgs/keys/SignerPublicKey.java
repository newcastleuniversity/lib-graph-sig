package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class SignerPublicKey implements Serializable, IPublicKey, IContextProducer {

	private static final long serialVersionUID = 7953446087582080777L;


	private final KeyGenParameters keyGenParameters;
	private final BigInteger modN;
	private final GroupElement baseR;
	private final GroupElement baseR_0;
	private final GroupElement baseS;
	private final GroupElement baseZ;
	private final Group group;

	/**
	 * Creates a new signer public key taking as input the modulus N,  the bases R, R_0, the generator base S, the base Z,
	 * the quadratic residue group and the key generation parameters.
	 * TODO add QRGroup in both pk and sk  @param modN the mod n
	 *
	 * @param modN             the modulus N
	 * @param baseR            the base R
	 * @param baseR_0          the base R_0
	 * @param baseS            the base S
	 * @param baseZ            the base Z
	 * @param group          the quadratic residue group
	 * @param keyGenParameters the key gen parameters
	 */
	public SignerPublicKey(
			final BigInteger modN,
			final GroupElement baseR,
			final GroupElement baseR_0,
			final GroupElement baseS,
			final GroupElement baseZ,
			final Group group,
			final KeyGenParameters keyGenParameters) {
		this.modN = modN;
		this.baseR = baseR.publicClone();
		this.baseR_0 = baseR_0.publicClone();
		this.baseS = baseS.publicClone();
		this.baseZ = baseZ.publicClone();
		this.group = (Group) group.publicClone();
		this.keyGenParameters = keyGenParameters;
	}

	public BigInteger getModN() {
		return modN;
	}

	public GroupElement getBaseR_0() {
		return baseR_0;
	}

	public GroupElement getBaseS() {
		return baseS;
	}

	public GroupElement getBaseZ() {
		return baseZ;
	}

	public GroupElement getBaseR() {
		return this.baseR;
	}

	public Group getGroup() {
		return group;
	}

	public KeyGenParameters getKeyGenParameters() {
		return keyGenParameters;
	}

	@Override
	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		return ctxList;
	}

	@Override
	public void addToChallengeContext(List<String> ctxList) {
		ctxList.add(String.valueOf(this.getModN()));
		ctxList.add(String.valueOf(this.getBaseS().getValue()));
		ctxList.add(String.valueOf(this.getBaseZ().getValue()));
		ctxList.add(String.valueOf(this.getBaseR().getValue()));
		ctxList.add(String.valueOf(this.getBaseR_0().getValue()));
	}
}
