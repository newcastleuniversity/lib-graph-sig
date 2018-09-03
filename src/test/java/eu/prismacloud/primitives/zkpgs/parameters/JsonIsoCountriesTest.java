package eu.prismacloud.primitives.zkpgs.parameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Map;
import javax.json.JsonArray;
import javax.json.JsonReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JsonIsoCountriesTest {
  private JsonIsoCountries jsonIsoCountries;
  private JsonReader reader;
  private JsonArray jsonArray;

  @BeforeEach
  void setUp() {
    jsonIsoCountries = new JsonIsoCountries();
  }

  @Test
  void parseParamFile() {
    InputStream encodingStream = jsonIsoCountries.parseEncodingFile();
    assertNotNull(encodingStream);
  }

  @Test
  void getCountryMap() {
    Map<URN, BigInteger> countryMap = jsonIsoCountries
        .getCountryMap();
    assertNotNull(countryMap);
    assertTrue(!countryMap.isEmpty());

  }


}
