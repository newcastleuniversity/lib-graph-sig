package eu.prismacloud.primitives.zkpgs.parameters;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;

/** Helper class to load the json file with the list of country names and country codes. */
public class JsonIsoCountries {

  private static final int COUNTRY_JSON_INDEX = 0;
  private static final int COUNTRY_CODE_START = 0;
  private static final int COUNTRY_CODE_END = 2;

  private static final String GS_ISO_COUNTRIES_FILE = "iso_3166_alpha_2.json";
  private final Logger gslog = GSLoggerConfiguration.getGSlog();

  private InputStream paramStream;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private JsonReader reader;
  private Map<URN, BigInteger> countriesLabel;
  private JsonArray jsonArray;
  private JsonValue country;
  private JsonString countryCodeJson;
  private String countryCode;

  /** Json parameters. */
  public JsonIsoCountries() {
    this.countriesLabel = new HashMap<URN, BigInteger>();
    this.reader = parseParamFile();
    build();
  }

  /** prime representatives for 249 countries in the ISO-3166 */
  private static final int[] primeNumbers = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579
  };

  /**
   * Parse param file.
   *
   * @return the json reader
   */
  public JsonReader parseParamFile() {

    this.paramStream =
        JsonIsoCountries.class.getClassLoader().getResourceAsStream(GS_ISO_COUNTRIES_FILE);

    return Json.createReader(paramStream);
  }

  /** Build countries label from ISO-3166 alpha 2 standard file. */
  public void build() {
    this.jsonArray = this.reader.readArray();
  }

  /**
   * Get countries list.
   *
   * @return the list
   */
  public Map<URN, BigInteger> getCountryMap() {
    if (this.jsonArray != null) {
      for (int i = 0; i < this.jsonArray.size(); i++) {
        country = jsonArray.get(i);
        countryCodeJson = country.asJsonArray().getJsonString(COUNTRY_JSON_INDEX);
        countryCode = countryCodeJson.getString().substring(COUNTRY_CODE_START,COUNTRY_CODE_END);
//        gslog.log(Level.INFO, "countrycode: " + countryCode);
        countriesLabel.put(
            URN.createZkpgsURN("countries.i_" + String.valueOf(i) + "_" + countryCode),
            BigInteger.valueOf(primeNumbers[i]));
      }
    }
    return countriesLabel;
  }

  /**
   * Gets index of the country code from the ISO-3166 list of countries.
   *
   * @param countryCode the country code according to the ISO-3166 standard
   * @return the index of the country code
   */
  public int getIndex(String countryCode) {
    Assert.notNull(countryCode, "Country code must not be null");
    //    Assert.notEmpty(countryCodeJson, "Country code must not be empty");

    int index = 0;
    for (int i = 0; i < this.jsonArray.size(); i++) {
      JsonValue jsonObject = jsonArray.get(i);
      JsonString cCode = (JsonString) jsonObject.asJsonArray().get(0);
      if (countryCode.equals(cCode.getString())) {
        index = i;
        gslog.info("index: " + i);
        gslog.info("json value: " + jsonObject.asJsonArray().get(0));
      }
    }

    return index;
  }
}
