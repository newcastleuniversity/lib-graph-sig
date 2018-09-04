package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** Base service class for the iterator. */
public class BaseCollectionImpl implements BaseCollection, Serializable, IContextProducer {

	private static final long serialVersionUID = 4214821047875971751L;
	private List<BaseRepresentation> bases;

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

	public void setBases(List<BaseRepresentation> bases) {
		this.bases = bases;
	}

	public BaseRepresentation get(int index) {
		return bases.get(index);
	}

	public void set(int index, BaseRepresentation value) {
		bases.set(index, value);
	}
	
	public void addAll(Collection<BaseRepresentation> collection) {
		this.bases.addAll(collection);
	}

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
}
