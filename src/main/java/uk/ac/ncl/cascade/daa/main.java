package uk.ac.ncl.cascade.daa;

import uk.ac.ncl.cascade.daa.join.*;
import java.math.BigInteger;

public class main {

	public static void main(String argv[]) {
        try {
    	    System.loadLibrary("topographia_daa_join");
            String[] str = {" "};
	        topographia_daa_join.tp_daa_join(str);
            BigInteger bi = new BigInteger(topographia_daa_join.getNG(), 16);
            System.out.println("bi biginteger: " + bi);
            System.out.println("bi hex: " + bi.toString(16));

        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
	}
}
