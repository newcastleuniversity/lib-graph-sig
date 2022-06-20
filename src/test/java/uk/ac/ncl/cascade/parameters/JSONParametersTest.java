package uk.ac.ncl.cascade.parameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.json.JsonObject;
import javax.json.JsonReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;

/** Test parsing the json parameters file */
class JSONParametersTest {
  private JSONParameters jsonParameters;
  private JsonReader reader;
  private JsonObject jsonObject;
  private JsonObject jsonKeyGenParams;
  private JsonObject jsonGraphEncodingParams;

  @BeforeEach
  void setUp() {
    jsonParameters = new JSONParameters();
  }

  @Test
  void parseParamFile() {
    reader = jsonParameters.parseParamFile();
    assertNotNull(reader);
  }

  @Test
  void build() {
    reader = jsonParameters.parseParamFile();
    jsonObject = reader.readObject();
    jsonKeyGenParams = jsonObject.getJsonObject("keyGenParameters");
    int l_n = jsonKeyGenParams.getInt("l_n");
    int l_gamma = jsonKeyGenParams.getInt("l_gamma");
    int l_rho = jsonKeyGenParams.getInt("l_rho");
    int l_m = jsonKeyGenParams.getInt("l_m");
    int l_res = jsonKeyGenParams.getInt("l_res");
    int l_e = jsonKeyGenParams.getInt("l_e");
    int l_prime_e = jsonKeyGenParams.getInt("l_prime_e");
    int l_v = jsonKeyGenParams.getInt("l_v");
    int l_statzk = jsonKeyGenParams.getInt("l_statzk");
    int l_H = jsonKeyGenParams.getInt("l_H");
    int l_r = jsonKeyGenParams.getInt("l_r");
    int l_pt = jsonKeyGenParams.getInt("l_pt");
    assertEquals(2048, l_n);
//    assertEquals(512, l_n);
    assertEquals(1632, l_gamma);
    assertEquals(256, l_rho);
    assertEquals(256, l_m);
//    assertEquals(128, l_m);
    assertEquals(1, l_res);
    assertEquals(597, l_e);
    assertEquals(120, l_prime_e);
    assertEquals(2724, l_v);
    assertEquals(80, l_statzk);
    assertEquals(256, l_H);
    assertEquals(80, l_r);
    assertEquals(80, l_pt);

    jsonGraphEncodingParams = jsonObject.getJsonObject("graphEncodingParameters");
    int l_V = jsonGraphEncodingParams.getInt("l_V");
    int l_prime_V = jsonGraphEncodingParams.getInt("l_prime_V");
    int l_E = jsonGraphEncodingParams.getInt("l_E");
    int l_L = jsonGraphEncodingParams.getInt("l_L");
    int l_prime_L = jsonGraphEncodingParams.getInt("l_prime_L");
//    assertEquals(1000, l_V);
    assertEquals(100, l_V);
    assertEquals(120, l_prime_V);
//    assertEquals(56, l_prime_V);
//    assertEquals(50000, l_E);
    assertEquals(500, l_E);
    assertEquals(256, l_L);
    assertEquals(16, l_prime_L);
  }
}
