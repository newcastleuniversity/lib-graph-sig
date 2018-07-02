package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The type Proof store.
 *
 * @param <T> the type parameter
 */
public class ProofStore<T> {
  private Logger gslog = GSLoggerConfiguration.getGSlog();
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
    Assert.notNull(key, "Store key cannot be null");
    Assert.notNull(element, "Store element cannot be null");

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
    save(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), urnkey), element);
  }

  /**
   * Retrieve proof object according to a URN key.
   *
   * @param urnkey the urnkey
   * @return the t
   */
  public T retrieve(String urnkey) {
    return get(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), urnkey));
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
      throw new IllegalStateException("Store element not present");
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
    Assert.notNull(key, "key cannot be null");
    Assert.notNull(element, "Store element cannot be null");

    Set<T> el = elements.get(key);
    if (null == el) {
      // No elements of this type have been added.
      el = new HashSet<T>(1);
      elements.put(key, el);
    }
    // Repeated instances are not allowed.
    if (!el.add(element)) throw new ProofStoreException("Store element instance already present");
  }

  /**
   * Remove.
   *
   * @param key the key
   * @param element the element
   */
  public void remove(URN key, T element) {
    Assert.notNull(key, "key cannot be null");
    Assert.notNull(element, "Store element cannot be null");

    Set<T> el = elements.get(key);
    if (null == el || !el.remove(element))
      throw new IllegalStateException("Store element not present");

    if (el.isEmpty()) elements.remove(key);
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
   * Size int.
   *
   * @return the int
   */
  public int size() {
    return this.elements.size();
  }
}
