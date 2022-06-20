package uk.ac.ncl.cascade.parameters;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.JsonIsoCountries;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JsonIsoCountriesTest {
  private JsonIsoCountries jsonIsoCountries;
  private GraphEncodingParameters graphEncodingParameters;

  @BeforeEach
  void setUp() {
    graphEncodingParameters = new GraphEncodingParameters(100, 56, 500, 256, 16);
    jsonIsoCountries = new JsonIsoCountries();
  }

  @Test
  @DisplayName("Test parsing json file that holds the country labels encoding")
  void parseParamFile() {
    InputStream encodingStream = jsonIsoCountries.parseEncodingFile();
    assertNotNull(encodingStream);
  }

  @Test
  @DisplayName("Test returning a map of label prime representatives encoding countries in range")
  void getCountryMap() {
    Map<URN, BigInteger> countryMap = jsonIsoCountries.getCountryMap();
    assertNotNull(countryMap);
    assertTrue(!countryMap.isEmpty());

    for (BigInteger labelPrimeRepresentative : countryMap.values()) {
      assertTrue(labelPrimeRepresentative.isProbablePrime(80));
      assertTrue(
          CryptoUtilsFacade.isInRange(
              labelPrimeRepresentative,
              graphEncodingParameters.getLeastLabelRepresentative(),
              graphEncodingParameters.getUpperBoundLabelRepresentatives()));
    }
  }
}
