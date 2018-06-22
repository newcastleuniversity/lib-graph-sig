package eu.prismacloud.primitives.zkpgs.parameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    reader = jsonIsoCountries.parseParamFile();
    assertNotNull(reader);
  }

  @Test
  void build() {
    reader = jsonIsoCountries.parseParamFile();
    jsonArray = reader.readArray();
    assertNotNull(jsonArray);
  }

  @Test
  void getIndex() {
    int index = jsonIsoCountries.getIndex("GB");
    assertEquals(76, index);
  }
}
