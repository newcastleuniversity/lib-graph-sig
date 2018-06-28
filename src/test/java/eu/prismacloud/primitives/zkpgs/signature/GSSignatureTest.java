package eu.prismacloud.primitives.zkpgs.signature;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Created by Ioannis Sfyrakis on 22/06/2018
 */
class GSSignatureTest {
  //  N =77, l_n = 7
  // p = 11, p’ =5; q = 7, q’ = 3
  //
  // \phi(N) = 60
  // S = 60; QR_N = <60>; #QR_N = 15
  // R = 58
  //
  // l_m = 2; l_e =4
  // (of course there are only 2 primes e possible fitting these parameters, 11 and
  // 13, and the only messages possible: 1, 2 or 3).

  @BeforeEach
  void setup() {
    /** TODO setup gs signature object */

  }

  @Test
  void getA() {}

  @Test
  void getE() {}

  @Test
  void getV() {}

  @Test
  void computeQ() {}

  @Test
  void computeA() {}

  @Test
  void blind() {}
}