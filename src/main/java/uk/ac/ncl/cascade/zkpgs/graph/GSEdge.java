package uk.ac.ncl.cascade.zkpgs.graph;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jgrapht.graph.DefaultEdge;

/** Representing a edge in a graph.
 * 
 * <p>An edge contains exactly two vertices.
 * An edge can contain zero to multiple labels, with their corresponding
 * label representatives, that is, prime numbers representing each label
 * as prescribed by an ExtendedPublicKey of a Signer.
 **/
public class GSEdge extends DefaultEdge implements Cloneable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3689174677400566632L;

	private final GSVertex v_i;
	private final GSVertex v_j;
	private ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
	private ArrayList<String> labels = new ArrayList<>();

	public GSEdge(GSVertex e_i, GSVertex e_j) {
		this.v_i = e_i;
		this.v_j = e_j;
	}

	public GSVertex getV_i() {
		return v_i;
	}

	public GSVertex getV_j() {
		return v_j;
	}

	/*
	 *  TODO the List interface of labels and representatives does not 
	 *  enforce consistency. Error-prone.
	 */
	/** 
	 * Returns an (unmodifiable) list of the BigInteger label representatives of this edge.
	 * 
	 * @return unmodifiable BigInteger List of label representatives.
	 */
	public List<BigInteger> getLabelRepresentatives() {
		return Collections.unmodifiableList(labelRepresentatives);
	}

	protected void setLabelRepresentatives(ArrayList<BigInteger> labelRepresentatives) {
		this.labelRepresentatives = labelRepresentatives;
	}

	/** 
	 * Returns an (unmodifiable) list of the string labels of this edge.
	 * 
	 * @return unmodifiable String List of labels.
	 */
	public List<String> getLabels() {
		return Collections.unmodifiableList(labels);
	}

	protected void setLabels(ArrayList<String> labels) {
		this.labels = labels;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("uk.ac.ncl.cascade.zkpgs.graph.GSEdge{");
		sb.append("e_i=").append(v_i);
		sb.append(", e_j=").append(v_j);
		sb.append(", labelRepresentatives=").append(labelRepresentatives);
		sb.append(", labels=").append(labels);
		sb.append('}');
		return sb.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((v_i == null) ? 0 : v_i.hashCode());
		result = prime * result + ((v_j == null) ? 0 : v_j.hashCode());
		result = prime * result + ((labelRepresentatives == null) ? 0 : labelRepresentatives.hashCode());
		result = prime * result + ((labels == null) ? 0 : labels.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof GSEdge))
			return false;
		GSEdge other = (GSEdge) obj;
		if (v_i == null) {
			if (other.v_i != null)
				return false;
		} else if (!v_i.equals(other.v_i))
			return false;
		if (v_j == null) {
			if (other.v_j != null)
				return false;
		} else if (!v_j.equals(other.v_j))
			return false;
		if (labelRepresentatives == null) {
			if (other.labelRepresentatives != null)
				return false;
		} else if (!labelRepresentatives.equals(other.labelRepresentatives))
			return false;
		if (labels == null) {
			if (other.labels != null)
				return false;
		} else if (!labels.equals(other.labels))
			return false;
		return true;
	}

	@Override
	@SuppressWarnings("unchecked")
	public GSEdge clone() {
		GSEdge theClone = null;

		theClone = (GSEdge) super.clone();

		// Cloning mutable members
		theClone.labelRepresentatives = (ArrayList<BigInteger>) labelRepresentatives.clone();
		theClone.labels = (ArrayList<String>) labels.clone();

		return theClone;
	}
}
