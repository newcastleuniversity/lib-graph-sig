package uk.ac.ncl.cascade.zkpgs.prover;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.store.EnumeratedURNType;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;

/**
 * CommitmentProver making provisions for the issuing phase of the
 * graph signature scheme and enforcing naming and length conventions
 * for it.
 */
public class IssuingCommitmentProver extends AbstractCommitmentProver implements IProver {

	public static final String URNID = "issuing.commitmentprover";

	private transient List<URNType> urnTypes;
	private transient List<EnumeratedURNType> enumeratedTypes;
	private transient List<URN> governedURNs;

	/**
	 * Instantiates a new commitment prover for the issuing phase.
	 * 
	 * @param com Commitment to be proven.
	 * @param spk Signer public key
	 * @param ps ProofStore
	 */
	public IssuingCommitmentProver(final GSCommitment com,
			final SignerPublicKey spk, final ProofStore<Object> ps) {
		super(com, -1, spk, ps);
	}

	@Override
	public List<URN> getGovernedURNs() {
		if (urnTypes == null) {
			urnTypes =
					Collections.unmodifiableList(
							Arrays.asList(
									URNType.TILDEM0,
									URNType.HATM0,
									URNType.TILDEU,
									URNType.TILDEVPRIME));
		}
		if (enumeratedTypes == null) {
			enumeratedTypes = new ArrayList<EnumeratedURNType>(baseCollection.size());
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, base.getBaseIndex()));
			}
			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMIJ, base.getBaseIndex()));
			}
		}

		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, this.getClass()));
		}
		return governedURNs;
	}

	@Override
	public URN getWitnessURN() {
		return URNType.buildURN(URNType.TILDEU, this.getClass());
	}

	@Override
	public URN getTildeRandomnessURN() {
		return URNType.buildURN(URNType.TILDEVPRIME, this.getClass());
	}

	@Override
	protected URN getTildeVertexURN(int baseIndex) {
		return URNType.buildURN(URNType.TILDEMI, this.getClass(), baseIndex);
	}

	@Override
	protected URN getTildeEdgeURN(int baseIndex) {
		return URNType.buildURN(URNType.TILDEMIJ, this.getClass(), baseIndex);
	}

	@Override
	protected URN getTildeM0URN() {
		return URNType.buildURN(URNType.TILDEM0, this.getClass());
	}
	
	@Override
	protected URN getTildeMURN() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getTildeRandomnessBitlength() {
		return getKeyGenParams().getL_n()
				+ (2 * getKeyGenParams().getL_statzk())
				+ getKeyGenParams().getL_H();
	}

	@Override
	protected boolean isProvingEquality() {
		return false;
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
		return URNType.buildURN(URNType.TILDEMIJ, this.getClass(), baseIndex);
	}

	@Override
	protected URN getHatM0URN() {
		return URN.createZkpgsURN("bases.exponent.m_0"); 
		// TODO this URN is out of the normal pattern
	}
	
	@Override
	protected URN getHatMURN() {
		throw new IllegalStateException("The singleton base R should not be used"
				+ " during issuing.");
	}

	@Override
	protected boolean isRestrictedToSingleton() {
		return false;
	}
}
