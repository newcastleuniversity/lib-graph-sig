package eu.prismacloud.primitives.zkpgs.encoding;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.store.URN;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Map;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CountryEncodingTest {
  private InputStream paramStream;
  private JsonReader reader;
  private Map<URN, BigInteger> countriesLabel;
  private JsonArray jsonArray;
  private JsonValue country;
  private JsonString countryCodeJson;
  private String countryCode;
  private Jsonb jsonb;
  private CountryEncoding ce;
  private ArrayList ces;

  @BeforeEach
  void setUp() {
    jsonb = JsonbBuilder.create();
    paramStream =
        CountryEncodingTest.class.getClassLoader().getResourceAsStream(DefaultValues.COUNTRY_ENCODING_FILE);
  }

  @Test
  @DisplayName("Test deserialization from json file holding the country encoding")
  void testDeSerialization() {
    ces =
        jsonb.fromJson(
            paramStream, new ArrayList<CountryEncoding>() {}.getClass().getGenericSuperclass());
    assertNotNull(ces);
    assertTrue(!ces.isEmpty());
  }

  @Test
  @DisplayName("Test serialization should produce json representation of country encoding")
  void testSerialization() {
    CountryEncoding ce = new CountryEncoding();
    ce.setCountryCode("AD");
    ce.setCountryName("Andorra");
    ce.setPrimeRepresentative(2);
    String result = jsonb.toJson(ce);
    assertNotNull(result);
  }

  @Test
  @DisplayName("Test adding country code to country encoding")
  void setCountryCode() {
    CountryEncoding ce = new CountryEncoding();
    ce.setCountryCode("AD");
    ce.setCountryName("Andorra");
    ce.setPrimeRepresentative(2);
    assertEquals("AD", ce.getCountryCode());
  }

  @Test
  @DisplayName("Test returning country name from country encoding")
  void getCountryName() {
    ces =
        jsonb.fromJson(
            paramStream, new ArrayList<CountryEncoding>() {}.getClass().getGenericSuperclass());
    CountryEncoding ce = (CountryEncoding) ces.get(0);
    assertEquals("Andorra", ce.getCountryName());
  }

  @Test
  @DisplayName("Test get country code from json")
  void getCountryCode() {
    ces =
        jsonb.fromJson(
            paramStream, new ArrayList<CountryEncoding>() {}.getClass().getGenericSuperclass());
    CountryEncoding ce = (CountryEncoding) ces.get(0);
    assertEquals("AD", ce.getCountryCode());
  }

  @Test
  @DisplayName("Test adding country name to country encoding")
  void setCountryName() {
    CountryEncoding ce = new CountryEncoding();
    ce.setCountryCode("AD");
    ce.setCountryName("Andorra");
    ce.setPrimeRepresentative(2);
    assertEquals("Andorra", ce.getCountryName());
  }

  @Test
  @DisplayName("Test returning prime representative")
  void getPrimeRepresentative() {
    ces =
        jsonb.fromJson(
            paramStream, new ArrayList<CountryEncoding>() {}.getClass().getGenericSuperclass());
    CountryEncoding ce = (CountryEncoding) ces.get(0);
    assertEquals(2, ce.getPrimeRepresentative());
  }

  @Test
  @DisplayName("Test adding prime representative to country encoding")
  void setPrimeRepresentative() {
    CountryEncoding ce = new CountryEncoding();
    ce.setCountryCode("AD");
    ce.setCountryName("Andorra");
    ce.setPrimeRepresentative(2);
    assertEquals(2, ce.getPrimeRepresentative());
  }
}
