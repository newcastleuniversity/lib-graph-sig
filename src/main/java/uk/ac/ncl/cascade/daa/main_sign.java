package uk.ac.ncl.cascade.daa;

import uk.ac.ncl.cascade.daa.sign.*;
import java.math.BigInteger;

public class main_sign {

	public static void main(String argv[]) {
        try {
    	    System.loadLibrary("topographia_daa_sign");
            String[] str = {" "};
	        topographia_daa_sign.tp_daa_sign(str);
            String res = topographia_daa_sign.getSignResult();
            System.out.println("res : " + res);

        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
	}
}
