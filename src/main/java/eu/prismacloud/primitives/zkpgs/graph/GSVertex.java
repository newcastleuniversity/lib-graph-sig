package eu.prismacloud.primitives.zkpgs.graph;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.exception.GSInternalError;

/** A graph vertex for graph representation. */
public class GSVertex implements Serializable, Cloneable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6984692808173957382L;

	private ArrayList<String> labels = new ArrayList<>();
	private String id;
	private BigInteger vertexRepresentative;
	private ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();

	public GSVertex(final String id, final ArrayList<String> labels) {
		this.id = id;
		this.labels = labels;
	}

	/** 
	 * Returns an (unmodifiable) list of the string labels of this vertex.
	 * 
	 * @return unmodifiable String List of labels.
	 */
	public List<String> getLabels() {
		return Collections.unmodifiableList(labels);
	}

	protected void setLabels(ArrayList<String> labels) {
		this.labels = labels;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	/** 
	 * Returns an (unmodifiable) list of the BigInteger label representatives of this vertex.
	 * 
	 * @return unmodifiable BigInteger List of label representatives.
	 */
	public List<BigInteger> getLabelRepresentatives() {
		return Collections.unmodifiableList(labelRepresentatives);
	}

	protected void setLabelRepresentatives(ArrayList<BigInteger> labelRepresentatives) {
		this.labelRepresentatives = labelRepresentatives;
	}

	public BigInteger getVertexRepresentative() {
		return vertexRepresentative;
	}

	protected void setVertexRepresentative(BigInteger vertexPrimeRepresentative) {
		this.vertexRepresentative = vertexPrimeRepresentative;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.graph.GSVertex{");
		sb.append("labels=").append(labels);
		sb.append(", id='").append(id).append('\'');
		sb.append(", vertexPrimeRepresentative=").append(vertexRepresentative);
		sb.append(", labelPrimeRepresentatives=").append(labelRepresentatives);
		sb.append('}');
		return sb.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((labelRepresentatives == null) ? 0 : labelRepresentatives.hashCode());
		result = prime * result + ((labels == null) ? 0 : labels.hashCode());
		result = prime * result + ((vertexRepresentative == null) ? 0 : vertexRepresentative.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof GSVertex))
			return false;
		GSVertex other = (GSVertex) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
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
		if (vertexRepresentative == null) {
			if (other.vertexRepresentative != null)
				return false;
		} else if (!vertexRepresentative.equals(other.vertexRepresentative))
			return false;
		return true;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public GSVertex clone() {
		GSVertex theClone = null;

		try {
			theClone = (GSVertex) super.clone();
		} catch (CloneNotSupportedException e) {
			// Should never happen
			throw new GSInternalError(e);
		}

		// Cloning mutable members
		theClone.labelRepresentatives = (ArrayList<BigInteger>) labelRepresentatives.clone();
		theClone.labels = (ArrayList<String>) labels.clone();

		return theClone;
	}
}
