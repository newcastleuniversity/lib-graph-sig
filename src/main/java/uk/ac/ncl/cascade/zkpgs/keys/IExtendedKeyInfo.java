package uk.ac.ncl.cascade.zkpgs.keys;

import uk.ac.ncl.cascade.zkpgs.encoding.IGraphEncoding;

/**
 * Interface to standardize the extended information offered
 * by ExtendedPublicKey and ExtendedKeyPair instances.
 */
public interface IExtendedKeyInfo extends IGraphEncoding {

	/**
	 * Returns the encoding set for a given ExtendedPublicKey.
	 * 
	 * @return encoding to be used for this ExtendedPublicKey.
	 */
	IGraphEncoding getEncoding();
}
