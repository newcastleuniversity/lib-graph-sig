package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQDlog;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;

public class InfoFlowUtil {
	public static boolean doesGroupElementLeakPrivateInfo(GroupElement element) {
		return InfoFlowUtil.doesGroupElementLeakPQ(element)
				|| InfoFlowUtil.doesGroupElementLeakPQGroup(element)
				|| InfoFlowUtil.doesGroupElementLeakOrder(element);
	}
	
	/**
	 * Checks whether a group element can be cast to one carrying
	 * private information about the primes p and q.
	 * @param element a group element to be examined.
	 * @return <tt>true</tt> if the element can be cast to
	 * QRElementPQ or the like.
	 */
	@SuppressWarnings("unused")
	public static boolean doesGroupElementLeakPQ(GroupElement element) {
		try {
			QRElementPQ elementPQ = (QRElementPQ) element;
			QRElementPQDlog elementPQdlog = (QRElementPQDlog) element;
		} catch (ClassCastException e) {
			return false;
		}
		return true;
	}
	
	public static boolean doesGroupElementLeakPQGroup(GroupElement element) {
		return InfoFlowUtil.doesGroupLeakPQ(element.getGroup());
	}
	
	
	public static boolean doesGroupElementLeakOrder(GroupElement element) {
		try {
			element.getElementOrder();
		} catch (UnsupportedOperationException e) {
			return false;
		}
		return true;
	}
	
	public static boolean doesGroupLeakPrivateInfo(Group group) {
		return doesGroupLeakPQ(group)
				|| InfoFlowUtil.doesGroupLeakGroupOrder(group) 
				|| InfoFlowUtil.doesGroupElementLeakPrivateInfo(group.getGenerator());
	}
	
	
	@SuppressWarnings("unused")
	public static boolean doesGroupLeakPQ(Group group) {
		try {
			QRGroupPQ groupPQ = (QRGroupPQ) group;
		} catch (ClassCastException e) {
			return false;
		}
		return true;
	}
	
	public static boolean doesGroupLeakGroupOrder(Group group) {
		try {
			group.getOrder();
		} catch (UnsupportedOperationException e) {
			return false;
		}
		return true;
	}
	
	public static boolean doesBaseGroupElementLeakPrivateInfo(BaseRepresentation base) {
		return InfoFlowUtil.doesGroupElementLeakPrivateInfo(base.getBase());
	}
}
