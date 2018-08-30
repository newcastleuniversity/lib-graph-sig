package eu.prismacloud.primitives.zkpgs.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;

class BaseIteratorImpl implements BaseIterator {

	private final BASE type;
	private final List<BaseRepresentation> listOfBases;
	private int position;

	public BaseIteratorImpl(final BASE type, final List<BaseRepresentation> bases) {
		this.type = type;
		this.listOfBases = bases;
	}

	@Override
	// TODO hasNext() Does not account for null exponents.
	public boolean hasNext() {
		while (position < listOfBases.size()) {
			BaseRepresentation ba = listOfBases.get(position);
			if (ba.getBaseType().equals(type) || type.equals(BASE.ALL)) {
				return true;
			} else {
				position++;
			}
		}
		return false;
	}

	@Override
	public BaseRepresentation next() {
		BaseRepresentation ba = listOfBases.get(position);
		position++;
		return ba;
	}

	@Override
	public Iterator<BaseRepresentation> iterator() {
		List<BaseRepresentation> result = new ArrayList<BaseRepresentation>();
		if (type.equals(BASE.ALL)) {
			for (BaseRepresentation baseRepresentation : listOfBases) {
				if (baseRepresentation.getExponent() != null) {
					result.add(baseRepresentation);
				}
			}
			return result.iterator();
		} else {
			for (BaseRepresentation baseRepresentation : listOfBases) {
				if (type.equals(baseRepresentation.getBaseType())
						&& baseRepresentation.getExponent() != null) {
					result.add(baseRepresentation);
				}
			}

			return result.iterator();
		}
	}
}