package uk.ac.ncl.cascade.zkpgs.encoding;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbPropertyOrder;
import javax.json.bind.config.PropertyOrderStrategy;

/** */
@JsonbPropertyOrder(PropertyOrderStrategy.LEXICOGRAPHICAL)
public class CountryEncoding {
  @JsonbProperty("country-code")
  private String countryCode;

  @JsonbProperty("country-name")
  private String countryName;

  @JsonbProperty("prime-representative")
  private int primeRepresentative;

  public String getCountryCode() {
    return countryCode;
  }

  public void setCountryCode(String countryCode) {
    this.countryCode = countryCode;
  }

  public String getCountryName() {
    return countryName;
  }

  public void setCountryName(String countryName) {
    this.countryName = countryName;
  }

  public int getPrimeRepresentative() {
    return primeRepresentative;
  }

  public void setPrimeRepresentative(int primeRepresentative) {
    this.primeRepresentative = primeRepresentative;
  }

  @Override
  public String toString() {
    final StringBuilder sb =
        new StringBuilder("eu.prismacloud.primitives.zkpgs.encoding.CountryEncoding{");
    sb.append("countryCode='").append(countryCode).append('\'');
    sb.append(", countryName='").append(countryName).append('\'');
    sb.append(", primeRepresentative=").append(primeRepresentative);
    sb.append('}');
    return sb.toString();
  }
}
