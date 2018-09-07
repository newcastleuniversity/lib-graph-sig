package eu.prismacloud.primitives.zkpgs.prover;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.store.EnumeratedURNType;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;

public class MultiBaseCommitmentProver extends AbstractCommitmentProver implements IProver {

	public static final String URNID = "commitmentprover";

	private transient List<URNType> urnTypes;
	private transient List<EnumeratedURNType> enumeratedTypes;
	private transient List<URN> governedURNs;

	/**
	 * Instantiates a new commitment prover for the issuing phase.
	 *
	 * @param com   Commitment to be proven.
	 * @param index the index
	 * @param spk   Signer public key
	 * @param ps    ProofStore
	 */
	public MultiBaseCommitmentProver(final GSCommitment com, final int index,
			final SignerPublicKey spk, final ProofStore<Object> ps) {
		super(com, index, spk, ps);
	}

	@Override
	@SuppressWarnings("unchecked") 
	public List<URN> getGovernedURNs() {
		if (urnTypes == null) {
			urnTypes = Collections.EMPTY_LIST;
		}
		if (enumeratedTypes == null) {
			enumeratedTypes = new ArrayList<EnumeratedURNType>(baseCollection.size());
			//			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			//			for (BaseRepresentation base : vertexIterator) {
			//				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, base.getBaseIndex()));
			//			}
			//			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			//			for (BaseRepresentation base : edgeIterator) {
			//				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMIJ, base.getBaseIndex()));
			//			}

			// Commitments and randomness with index
			enumeratedTypes.add(new EnumeratedURNType(URNType.TILDECI, super.getCommitmentIndex()));
			enumeratedTypes.add(new EnumeratedURNType(URNType.TILDERI, super.getCommitmentIndex()));
		}

		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, this.getClass()));
		}
		return governedURNs;
	}

	@Override
	protected URN getWitnessURN() {
		return URNType.buildURN(URNType.TILDECI, this.getClass(), getCommitmentIndex());
	}

	@Override
	protected URN getTildeRandomnessURN() {
		return URNType.buildURN(URNType.TILDERI, this.getClass(), getCommitmentIndex());
	}

	@Override
	protected int getTildeRandomnessBitlength() {
		return getKeyGenParams().getL_n() + getKeyGenParams().getProofOffset();
	}

	@Override
	protected URN getTildeVertexURN(int baseIndex) {
		return URNType.buildURN(URNType.TILDEMI, PossessionProver.class, baseIndex);
	}

	@Override
	protected URN getTildeEdgeURN(int baseIndex) {
		return URNType.buildURN(URNType.TILDEMIJ, PossessionProver.class, baseIndex);
	}

	@Override
	protected URN getTildeM0URN() {
		return URNType.buildURN(URNType.TILDEM0, PossessionProver.class);	
	}

	@Override
	protected URN getTildeMURN() {
		return URNType.buildURN(URNType.TILDEMI, PossessionProver.class, getCommitmentIndex());
	}

	@Override
	protected boolean isProvingEquality() {
		return true;
	}

	@Override
	protected URN getHatRandomnessURN() {
		return URNType.buildURN(URNType.HATRI, this.getClass(), getCommitmentIndex());
	}


	@Override
	protected URN getHatVertexURN(int baseIndex) {
		return URNType.buildURN(URNType.HATMI, PossessionProver.class, baseIndex);
	}

	@Override
	protected URN getHatEdgeURN(int baseIndex) {
		return URNType.buildURN(URNType.HATMIJ, PossessionProver.class, baseIndex);
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
	protected boolean isRestrictedToSingleton() {
		return false;
	}


}
