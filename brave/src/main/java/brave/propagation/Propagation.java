package brave.propagation;

import java.util.List;
import javax.annotation.Nullable;

/**
 * Injects and extracts {@link TraceContext trace identifiers} as text into carriers that travel
 * in-band across process boundaries. Identifiers are often encoded as messaging or RPC request
 * headers.
 *
 * <h3>Propagation example: Http</h3>
 *
 * <p>When using http, the carrier of propagated data on both the client (injector) and server
 * (extractor) side is usually an http request. Propagation is usually implemented via library-
 * specific request interceptors, where the client-side injects span identifiers and the server-side
 * extracts them.
 *
 * @param <K> Usually, but not always a String
 */
public interface Propagation<K> {
  Propagation<String> B3_STRING = Propagation.Factory.B3.create(Propagation.KeyFactory.STRING);

  abstract class Factory {
    public static final Factory B3 = new B3Propagation.Factory();

    /**
     * Does the propagation implementation support sharing client and server span IDs. For example,
     * should an RPC server span share the same identifiers extracted from an incoming request?
     *
     * In usual <a href="https://github.com/openzipkin/b3-propagation">B3 Propagation</a>, the
     * parent span ID is sent across the wire so that the client and server can share the same
     * identifiers. Other propagation formats, like <a href="https://github.com/TraceContext/tracecontext-spec">trace-context</a>
     * only propagate the calling trace and span ID, with an assumption that the receiver always
     * starts a new child span. When join is supported, you can assume that when {@link
     * TraceContext#parentId() the parent span ID} is null, you've been propagated a root span. When
     * join is not supported, you must always fork a new child.
     */
    public boolean supportsJoin() {
      return false;
    }

    public abstract <K> Propagation<K> create(KeyFactory<K> keyFactory);
  }

  /** Creates keys for use in propagated contexts */
  interface KeyFactory<K> {
    KeyFactory<String> STRING = name -> name;

    K create(String name);
  }

  /** Replaces a propagated key with the given value */
  interface Setter<C, K> {
    void put(C carrier, K key, String value);
  }

  /**
   * The propagation fields defined. If your carrier is reused, you should delete the fields here
   * before calling {@link Setter#put(Object, Object, String)}.
   *
   * <p>For example, if the carrier is a single-use or immutable request object, you don't need to
   * clear fields as they couldn't have been set before. If it is a mutable, retryable object,
   * successive calls should clear these fields first.
   */
  // The use cases of this are:
  // * allow pre-allocation of fields, especially in systems like gRPC Metadata
  // * allow a single-pass over an iterator (ex OpenTracing has no getter in TextMap)
  List<K> keys();

  /**
   * Replaces a propagated field with the given value. Saved as a constant to avoid runtime
   * allocations.
   *
   * For example, a setter for an {@link java.net.HttpURLConnection} would be the method reference
   * {@link java.net.HttpURLConnection#addRequestProperty(String, String)}
   *
   * @param setter invoked for each propagation key to add.
   */
  <C> TraceContext.Injector<C> injector(Setter<C, K> setter);

  /** Gets the first value of the given propagation key or returns null */
  interface Getter<C, K> {
    @Nullable String get(C carrier, K key);
  }

  /**
   * @param getter invoked for each propagation key to get.
   */
  <C> TraceContext.Extractor<C> extractor(Getter<C, K> getter);
}
