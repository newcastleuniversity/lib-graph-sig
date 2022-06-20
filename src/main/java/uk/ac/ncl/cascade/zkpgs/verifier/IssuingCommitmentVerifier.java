/**
 * 
 */
package uk.ac.ncl.cascade.zkpgs.verifier;

import java.util.List;

import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.store.EnumeratedURNType;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

/**
 * @author ntg8
 *
 */
public class IssuingCommitmentVerifier extends AbstractCommitmentVerifier implements IVerifier, IURNGoverner {
	
	public static final String URNID = "issuing.commitmentverifier";

	private transient List<URNType> urnTypes;
	private transient List<EnumeratedURNType> enumeratedTypes;
	private transient List<URN> governedURNs;
	
	public IssuingCommitmentVerifier(final GroupElement commitmentValue, final BaseCollection basesInCommitment, 
			final ExtendedPublicKey epk, final ProofStore<Object> ps) {

		super(commitmentValue, basesInCommitment, -1, epk, ps);
	}

	/* (non-Javadoc)
	 * @see eu.prismacloud.primitives.zkpgs.verifier.IVerifier#getGovernedURNs()
	 */
	@Override
	public List<URN> getGovernedURNs() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected URN getHatWitnessURN() {
		return URNType.buildURN(URNType.HATU, this.getClass());
	}

	@Override
	protected int getHatRandomnessBitlength() {
		return getKeyGenParams().getL_n()
		+ (2 * getKeyGenParams().getL_statzk())
		+ getKeyGenParams().getL_H()
		+ 1;
	}

	@Override
	protected URN getHatRandomnessURN() {
		return URNType.buildURN(URNType.HATVPRIME, this.getClass());
	}

	@Override
	protected URN getHatVertexURN(int baseIndex) {
		return URNType.buildURN(URNType.HATMI, this.getClass(), baseIndex);
	}
	
	@Override
	protected URN getHatEdgeURN(int baseIndex) {
		return URNType.buildURN(URNType.HATMI, this.getClass(), baseIndex);
	}

	@Override
	protected URN getHatM0URN() {
		return URNType.buildURN(URNType.HATM0, this.getClass());
	}

	@Override
	protected URN getHatMURN() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected boolean isVerifyingEquality() {
		return false;
	}

	@Override
	protected boolean isRestrictedToSingleton() {
		return false;
	}

}
