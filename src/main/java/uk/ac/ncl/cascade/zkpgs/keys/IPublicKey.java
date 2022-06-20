/**
 * 
 */
package uk.ac.ncl.cascade.zkpgs.keys;

import java.io.Serializable;

import uk.ac.ncl.cascade.zkpgs.context.IContextProducer;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;

/**
 * Interface of any public key
 *
 */
public interface IPublicKey extends IContextProducer, Serializable, IURNGoverner {

	KeyGenParameters getKeyGenParameters();
	
}
