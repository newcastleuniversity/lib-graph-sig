package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;

import javax.json.JsonObject;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static eu.prismacloud.primitives.zkpgs.util.JsonUtils.mapToJson;

public class GSMessage implements Serializable {

	private static final long serialVersionUID = -8931520272759188134L;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	Map<URN, Object> messageElements = new HashMap<URN, Object>();

	public GSMessage() {
	}

	public GSMessage(Map<URN, Object> messageElements) {
		this.messageElements = messageElements;
	}


	public Map<URN, Object> getMessageElements() {
		return this.messageElements;
	}


	public JsonObject getJsonMessage() {
		return mapToJson(this.messageElements);
	}

}

