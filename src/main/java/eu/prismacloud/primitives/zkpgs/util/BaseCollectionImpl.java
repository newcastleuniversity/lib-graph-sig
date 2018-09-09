package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.exception.TopocertInternalError;
import eu.prismacloud.primitives.zkpgs.store.URN;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

/** Base service class for the iterator. */
public class BaseCollectionImpl implements BaseCollection, Serializable, IContextProducer, Cloneable {

	private static final long serialVersionUID = 4214821047875971751L;
	private ArrayList<BaseRepresentation> bases;

	@Override
	public BaseIterator createIterator(BASE type) {
		return new BaseIteratorImpl(type, bases);
	}

	@Override
	public boolean add(BaseRepresentation base) {
		return bases.add(base);
	}

	@Override
	public boolean remove(BaseRepresentation base) {
		return bases.remove(base);
	}

	public BaseCollectionImpl() {
		bases = new ArrayList<BaseRepresentation>();
	}

	public List<BaseRepresentation> getBases() {
		return bases;
	}

	public void setBases(ArrayList<BaseRepresentation> bases) {
		this.bases = bases;
	}

	@Override
	public BaseRepresentation get(int index) {
		return bases.get(index);
	}
	
	@Override
	public BaseRepresentation getFirst() {
		return get(0);
	}

	public void set(int index, BaseRepresentation value) {
		bases.set(index, value);
	}
	
	public void addAll(Collection<BaseRepresentation> collection) {
		this.bases.addAll(collection);
	}

	@Override
	public int size() {
		return bases.size();
	}

	@Override
	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		addToChallengeContext(ctxList);
		return ctxList;
	}

	@Override
	public void addToChallengeContext(List<String> ctxList) {
		for (BaseRepresentation baseRepresentation : bases) {
			baseRepresentation.addToChallengeContext(ctxList);
		}
	}
	
	@Override
	public void removeExponents() {
		Iterator<BaseRepresentation> baseIter = bases.iterator();
		
		while (baseIter.hasNext()) {
			BaseRepresentation baseRepresentation = baseIter.next();
			baseRepresentation.setExponent(BigInteger.ZERO);
		}
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public BaseCollectionImpl clone() {
		BaseCollectionImpl theClone = null;
		try {
			theClone = (BaseCollectionImpl) super.clone();
		} catch(CloneNotSupportedException e) {
			// Should never happen
			throw new TopocertInternalError(e);
		}
		
		// Clone mutable fields
		theClone.bases = (ArrayList<BaseRepresentation>) this.bases.clone();
		
		return theClone;
	}

	@Override
	public boolean contains(BaseRepresentation base) {
		return bases.contains(base);
	}
	
	/**
	 * Gets concise overview of the ProofStore
	 *
	 * @return the String
	 */
	public String getStringOverview() {
		if (bases.isEmpty()) return "BaseCollection: Empty";

		StringBuffer sb = new StringBuffer("BaseCollection:");
		Iterator<BaseRepresentation> baseIterator = bases.iterator();
		while (baseIterator.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) baseIterator
					.next();
			sb.append("\n  ");
			sb.append(base.getBaseType() + "[" + base.getBaseIndex() + "]");
			sb.append(": ");
			sb.append(base.getExponent());
		}
		return sb.toString();
	}
}
