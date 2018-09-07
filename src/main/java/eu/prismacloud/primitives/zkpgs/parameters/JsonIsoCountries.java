package eu.prismacloud.primitives.zkpgs.parameters;

import eu.prismacloud.primitives.zkpgs.encoding.CountryEncoding;
import eu.prismacloud.primitives.zkpgs.store.URN;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;

/**
 * Helper class to load the json file with the list of country names and country codes and construct
 * a map with the country code and the corresponding prime representative
 */
public class JsonIsoCountries {

  private static final String GS_ISO_COUNTRIES_FILE = "iso_3166_alpha_2.json";
  private static final String COUNTRY_ENCODING_FILE = "country_encoding.json";
  private Jsonb jsonb;

  private InputStream encodingStream;

  public JsonIsoCountries() {
    this.encodingStream = parseEncodingFile();
  }

  /**
   * Parse json file that holds the name of the countries, their codes from the ISO-3166 and their
   * prime representative.
   *
   * @return the input stream of the country encoding json file
   */
  public InputStream parseEncodingFile() {

    return JsonIsoCountries.class.getClassLoader().getResourceAsStream(COUNTRY_ENCODING_FILE);
  }

  /**
   * Returns the map of countries that includes a URN country code as key and the country's prime
   * representative as value.
   *
   * @return a map containing the country's prime representative
   */
  public Map<URN, BigInteger> getCountryMap() {
    Map<URN, BigInteger> countriesLabel = new HashMap<>();
    jsonb = JsonbBuilder.create();
    List<CountryEncoding> countryEncodingList =
        jsonb.fromJson(
            encodingStream, new ArrayList<CountryEncoding>() {}.getClass().getGenericSuperclass());

    if (countryEncodingList != null) {
      for (CountryEncoding countryEncoding : countryEncodingList) {
        countriesLabel.put(
            URN.createUnsafeZkpgsURN(countryEncoding.getCountryCode()),
            BigInteger.valueOf(countryEncoding.getPrimeRepresentative()));
      }
    }
    return countriesLabel;
  }
}
