package uk.ac.ncl.cascade.zkpgs.util;

import uk.ac.ncl.cascade.zkpgs.store.URN;

import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 */
public final class JsonUtils {

	private static Logger gslog = GSLoggerConfiguration.getGSlog();

	private JsonUtils() {

	}

	public static JsonObject mapToJson(Map<?, ?> map) {
		JsonObjectBuilder object = Json.createObjectBuilder();

		for (Map.Entry<?, ?> entry : map.entrySet()) {
			String key;
			if (entry.getKey() instanceof URN) {
				key = ((URN) entry.getKey()).toHumanReadableString();
			} else {
				key = (String) entry.getKey();
			}

			Assert.notNull(key, "key in map must not be null");
			try {
				if (entry.getValue() instanceof BigInteger) {
					object.add(key, (BigInteger) entry.getValue());
				} else if (entry.getValue() instanceof String) {
					object.add(key, (String) entry.getValue());
				} else if (entry.getValue() instanceof Integer) {
					object.add(key, (Integer) entry.getValue());
				} else if (entry.getValue() instanceof Boolean) {
					object.add(key, (Boolean) entry.getValue());
				}
				object.add(key, (BigInteger) entry.getValue());
			} catch (JsonException e) {
				gslog.log(Level.SEVERE, "json message is not created");
			}
		}

		return object.build();
	}
}
