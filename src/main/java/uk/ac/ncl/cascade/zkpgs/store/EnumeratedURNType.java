package uk.ac.ncl.cascade.zkpgs.store;

public class EnumeratedURNType {

	public EnumeratedURNType(final URNType type, final int index) {
		this.type = type;
		this.index = index;
	}
	
	public final URNType type;
	public final int index;
	
	
}
