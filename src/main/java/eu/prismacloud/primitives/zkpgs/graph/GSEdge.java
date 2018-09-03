package eu.prismacloud.primitives.zkpgs.graph;

import java.math.BigInteger;
import java.util.ArrayList;
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

	private final GSVertex e_i;
	private final GSVertex e_j;
	private ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
	private ArrayList<String> labels = new ArrayList<>();

	public GSEdge(GSVertex e_i, GSVertex e_j) {
		this.e_i = e_i;
		this.e_j = e_j;
	}

	public GSVertex getE_i() {
		return e_i;
	}

	public GSVertex getE_j() {
		return e_j;
	}

	/*
	 *  TODO the List interface of labels and representatives does not 
	 *  enforce consistency. Error-prone.
	 */
	public List<BigInteger> getLabelRepresentatives() {
		return labelRepresentatives;
	}

	public void setLabelRepresentatives(ArrayList<BigInteger> labelRepresentatives) {
		this.labelRepresentatives = labelRepresentatives;
	}

	public List<String> getLabels() {
		return labels;
	}

	public void setLabels(ArrayList<String> labels) {
		this.labels = labels;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.graph.GSEdge{");
		sb.append("e_i=").append(e_i);
		sb.append(", e_j=").append(e_j);
		sb.append(", labelRepresentatives=").append(labelRepresentatives);
		sb.append(", labels=").append(labels);
		sb.append('}');
		return sb.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((e_i == null) ? 0 : e_i.hashCode());
		result = prime * result + ((e_j == null) ? 0 : e_j.hashCode());
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
		if (e_i == null) {
			if (other.e_i != null)
				return false;
		} else if (!e_i.equals(other.e_i))
			return false;
		if (e_j == null) {
			if (other.e_j != null)
				return false;
		} else if (!e_j.equals(other.e_j))
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
