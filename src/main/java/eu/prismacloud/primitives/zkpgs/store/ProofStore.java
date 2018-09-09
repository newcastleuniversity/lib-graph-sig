package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * The type Proof store.
 *
 * @param <T> the type parameter
 */
public class ProofStore<T> {
	private final Map<URN, Set<T>> elements;

	/**
	 * Instantiates a new Proof store.
	 *
	 * @param initialSize the initial size of proof store
	 */
	public ProofStore(int initialSize) {
		this.elements = new LinkedHashMap<URN, Set<T>>(initialSize);
	}

	/** Instantiates a new Proof store. */
	public ProofStore() {
		this.elements = new HashMap<URN, Set<T>>();
	}

	/**
	 * Save proof object in store.
	 *
	 * @param key the key
	 * @param element the element
	 * @throws eu.prismacloud.primitives.zkpgs.exception.ProofStoreException the exception
	 */
	public void save(URN key, T element) throws ProofStoreException {
		Assert.notNull(key, "Store key cannot be null.");
		Assert.notNull(element, "Store element cannot be null.");

		//    gslog.log(Level.INFO, "key value:  " + key);
		//    gslog.log(Level.INFO, "element:  " + element);

		if (elements.containsKey(key)) {
			throw new ProofStoreException(
					String.format(
							"The key %s with type %s was already added", key, key.getClass().getSimpleName()));
		}

		add(key, element);
	}

	/**
	 * Stores proof object.
	 *
	 * @param urnkey the urnkey
	 * @param element the element
	 * @throws ProofStoreException the exception
	 */
	public void store(String urnkey, T element) throws ProofStoreException {
		//  gslog.info("Storing under: " + urnkey);
		save(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), urnkey), element);
	}
	
	/**
	 * Stores proof object.
	 *
	 * @param urnkey the urnkey
	 * @param element the element
	 * @throws ProofStoreException the exception
	 */
	public void storeUnsafe(String urnkey, T element) throws ProofStoreException {
		//  gslog.info("Storing under: " + urnkey);
		save(URN.createUnsafeURN(URN.getZkpgsNameSpaceIdentifier(), urnkey), element);
	}

	/**
	 * Retrieve proof object according to a URN key.
	 *
	 * @param urnkey the urnkey
	 * @return the t
	 */
	public T retrieve(String urnkey) {
		//  gslog.info("Retrieving from: " + urnkey);
		return get(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), urnkey));
	}
	
	/**
	 * Retrieve proof object according to a URN key.
	 *
	 * @param urnkey the urnkey
	 * @return the t
	 */
	public T retrieveUnsafe(String urnkey) {
		//  gslog.info("Retrieving from: " + urnkey);
		return get(URN.createUnsafeURN(URN.getZkpgsNameSpaceIdentifier(), urnkey));
	}

	/**
	 * Get proof object according to a URN key.
	 *
	 * @param key the key
	 * @return the t
	 */
	public T get(URN key) {
		Assert.notNull(key, "Store URN key cannot be null");
		Set<T> el = elements.get(key);
		if (null == el) {
			throw new IllegalStateException("Store element not present: " + key.toHumanReadableString());
		}
		return (T) el.toArray()[0];
	}

	/**
	 * Add.
	 *
	 * @param key the key
	 * @param element the element
	 * @throws ProofStoreException the exception
	 */
	public void add(URN key, T element) throws ProofStoreException {
		Assert.notNull(key, "key cannot be null.");
		Assert.notNull(element, "Store element cannot be null.");

		Set<T> el = elements.get(key);
		if (null == el) {
			// No elements of this type have been added.
			el = new HashSet<T>(1);
			elements.put(key, el);
		}
		// Repeated instances are not allowed.
		if (!el.add(element)) throw new ProofStoreException("Store element instance already present: " + key.toHumanReadableString());
	}

	/**
	 * Remove.
	 *
	 * @param key the key
	 */
	public void remove(URN key) {
		Assert.notNull(key, "Key cannot be null");

		Set<T> el = elements.get(key);
		if (null == el) {
			throw new IllegalStateException("Store element key not present: " + key.toHumanReadableString());
		}

		elements.remove(key);
	}

	/**
	 * Is empty boolean.
	 *
	 * @return the boolean
	 */
	public boolean isEmpty() {
		return elements.isEmpty();
	}

	/**
	 * Gets elements.
	 *
	 * @return the elements
	 */
	public Collection<T> getElements() {
		if (elements.isEmpty()) return Collections.emptyList();

		Collection<T> elems = new ArrayList<T>(elements.size() + 3);
		for (Set<T> el : elements.values()) {
			elems.addAll(el);
		}
		return elems;
	}

	/**
	 * Returns one matching key for an Object value contained in the ProofStore.
	 * 
	 * @param value Object to search for.
	 * 
	 * @return URN key under which the Object value is stored.
	 */
	public URN getKey(Object value) {
		URN key = null;
		Iterator<Entry<URN, Set<T>>> entryIter = (elements.entrySet()).iterator();
		while (entryIter.hasNext()) {
			Entry<URN, Set<T>> entry= (Entry<URN, Set<T>>) entryIter.next();
			if (entry.getValue().contains(value)) {
				key = entry.getKey();
			}
		}
		return key;
	}

	/**
	 * Size int.
	 *
	 * @return the int
	 */
	public int size() {
		return this.elements.size();
	}
	
	/**
	 * Stores all elements of an incoming map into the ProofStore
	 * keeping the same URN keys.
	 * 
	 * <p>The method will not overwrite existing URN keys and throw 
	 * an exception instead.
	 * 
	 * @param map Incoming map
	 * 
	 * @throws ProofStoreException if an element of the same URN is already present.
	 */
	public void saveAll(Map<URN, T> map) throws ProofStoreException {
		Iterator<Entry<URN, T>> mapIterator = map.entrySet().iterator();
		while (mapIterator.hasNext()) {
			Map.Entry<URN, T> entry = (Map.Entry<URN, T>) mapIterator
					.next();
			this.add(entry.getKey(), entry.getValue());
		}
	}
	
	/**
	 * Gets concise overview of the ProofStore
	 *
	 * @return the String
	 */
	public String getStringOverview() {
		if (elements.isEmpty()) return "ProofStore: Empty";

		StringBuffer sb = new StringBuffer("ProofStore:");
		Iterator<Entry<URN, Set<T>>> elementIterator = elements.entrySet().iterator();
		while (elementIterator.hasNext()) {
			Map.Entry<URN, java.util.Set<T>> entry = (Map.Entry<URN, java.util.Set<T>>) elementIterator
					.next();
			sb.append("\n  ");
			sb.append(entry.getKey().getURNType());
			sb.append(": ");
			sb.append(entry.getKey().getSuffix());
			sb.append("\t\t\t ->  ");
			sb.append(entry.getKey().toHumanReadableString());
		}
		return sb.toString();
	}
}
