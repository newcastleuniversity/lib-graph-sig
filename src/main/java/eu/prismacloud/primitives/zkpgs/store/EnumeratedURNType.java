package eu.prismacloud.primitives.zkpgs.store;

public class EnumeratedURNType {

	public EnumeratedURNType(final URNType type, final int index) {
		this.type = type;
		this.index = index;
	}
	
	public final URNType type;
	public final int index;
	
	
}
