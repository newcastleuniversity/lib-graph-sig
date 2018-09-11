/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.verifier;

import java.util.List;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.store.EnumeratedURNType;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNClass;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

/**
 * A verifier for commitment proofs during the verification phase.
 */
public class CommitmentVerifier extends AbstractCommitmentVerifier implements IURNGoverner, IVerifier {

public static final String URNID = "commitmentverifier";
	
	private transient List<URNType> urnTypes;
	private transient List<EnumeratedURNType> enumeratedTypes;
	private transient List<URN> governedURNs;
	
	/**
	 * Instantiates a CommitmentVerifier for a particular commitment value and public bases.
	 * The responses (hat-values) are expected to be stored in the proof store.
	 * 
	 * @param commitmentValue Commitment to be verified.
	 * @param basesInCommitment Public bases used in the commitment representation.
	 * @param index Index of the commitment proven.
	 * @param epk Extended public key of the signer.
	 * @param ps ProofStore to be used.
	 */
	public CommitmentVerifier(GroupElement commitmentValue, BaseCollection basesInCommitment, final int index, final ExtendedPublicKey epk, final ProofStore<Object> ps) {
		super(commitmentValue, basesInCommitment, index, epk, ps);
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
	protected URN getURNbyBaseType(BaseRepresentation base, URNClass urnClass) {
		if (base.getBaseType().equals(BASE.BASER)) {
			return (urnClass.equals(URNClass.HAT)) ? getHatMURN() : getTildeMURN();
		} else {
			return URNType.buildURNbyBaseType(base, urnClass, this.getClass());
		}
	}

	private URN getTildeMURN() {
		return null;
	}
	
	@Override
	protected int getHatRandomnessBitlength() {
		return getKeyGenParams().getL_n() + getKeyGenParams().getProofOffset() + 1;
	}
	
	@Override
	protected int getHatMessageBitlength() {
		return getKeyGenParams().getL_m() + getKeyGenParams().getProofOffset() + 1;
	};

	@Override
	protected URN getHatWitnessURN() {
		return URNType.buildURN(URNType.HATCI, this.getClass(), getCommitmentIndex());
	}

	@Override
	protected URN getHatRandomnessURN() {
		return URNType.buildURN(URNType.HATRI, this.getClass(), getCommitmentIndex());
	}

	@Override
	protected URN getHatVertexURN(int baseIndex) {
		return URNType.buildURN(URNType.HATMI, PossessionProver.class, getCommitmentIndex());
	}

	@Override
	protected URN getHatEdgeURN(int baseIndex) {
		return URNType.buildURN(URNType.TILDEMIJ, PossessionProver.class, getCommitmentIndex());
	}

	@Override
	protected URN getHatM0URN() {
		return URNType.buildURN(URNType.HATM0, PossessionProver.class);
	}

	@Override
	protected URN getHatMURN() {
		return URNType.buildURN(URNType.HATMI, PossessionProver.class, getCommitmentIndex());
	}

	@Override
	protected boolean isVerifyingEquality() {
		return true;
	}
	
	@Override
	protected boolean isRestrictedToSingleton() {
		return true;
	}

}
