package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.store.URN;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class GSMessage implements Serializable {

	private static final long serialVersionUID = -8931520272759188134L;

	/**
	 * TODO finish gsmessage class to use a proxy
	 */
	Map<URN, Object> messageElements = new HashMap<URN, Object>();

	public GSMessage() {
	}

	public GSMessage(Map<URN, Object> messageElements) {
		this.messageElements = messageElements;
	}


	public Map<URN, Object> getMessageElements() {
		return this.messageElements;
	}
}
