/**
 * 
 */
package uk.ac.ncl.cascade.zkpgs.keys;

import java.io.Serializable;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;

/**
 * @author ntg8
 *
 */
public interface IPrivateKey extends Serializable {

	KeyGenParameters getKeyGenParameters();
	
}
