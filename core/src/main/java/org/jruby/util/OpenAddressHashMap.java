package org.jruby.util;

import java.util.Map;
import java.util.Set;
import java.util.Collection;

import org.jruby.ObjectFlags;

public class OpenAddressHashMap implements Map {
      private static final int HASH_SIGN_BIT_MASK = ~(1 << 31);
      private Object[] entries;
      private int[] bins;
      private int size;
      private final static int EMPTY_BIN = -1;
      private final static int DELETED_BIN = -2;
      private final static int A = 5;
      private final static int C = 1;
      public static final int COMPARE_BY_IDENTITY_F = ObjectFlags.COMPARE_BY_IDENTITY_F;
      
      public OpenAddressHashMap() {
          new OpenAddressHashMap(16);
      }
      
      public OpenAddressHashMap(int length) {
          entries = new Object[length];
          bins = new int[length * 2]; // todo bit operation
          // TODO fill array
          size = 0;
      }
      
      protected final int hashValue(final Object key) {
          final int h = isComparedByIdentity() ? System.identityHashCode(key) : key.hashCode();
          return h & HASH_SIGN_BIT_MASK;
      }
      
      private static int bucketIndex(final int h, final int length) {
          return h & (length - 1);
      }
      
      private boolean internalKeyExist(Object key, Object otherKey) {
          return (key == otherKey || (!isComparedByIdentity() && key.eql(otherKey)));
      }
      
      protected boolean isComparedByIdentity() {
          return (flags & COMPARE_BY_IDENTITY_F) != 0;
      }
      
      private static int secondaryBucketIndex(final int bucketIndex, final int length) {
        return (A * bucketIndex + C) & (length - 1);
      }
      
      public Object put(Object key, Object value, boolean checkForExisting) {
        final int hash = hashValue(key);
        int bin = bucketIndex(hash, bins.length);
        int index = bins[bin];
        Object otherKey;
        
        if (checkForExisting) {
            while(index != EMPTY_BIN && index != DELETED_BIN) {
                otherKey = entries[index * 2];
                if (internalKeyExist(key, otherKey)) {
                    Object otherValue = entries[index * 2 + 1];
                    entries[index * 2 + 1] = value;
                    return otherValue;
                }
                bin = secondaryBucketIndex(bin, bins.length);
                index = bins[bin];
            }
        }

        checkIterating();
        entries[size * 2] = key;
        entries[size * 2 + 1] = value;
        while(index != EMPTY_BIN && index != DELETED_BIN) {
            bin = secondaryBucketIndex(bin, bins.length);
            index = bins[bin];
        }
        bins[bin] = size;
        size++;
        return null;
      }
      
      @Override
      public Object put(Object key, Object value) {
          return null;
      }
      
      
      @Override
      public Object remove(Object o) {
          return null;
      }
      
      
      @Override
      public Object get(Object key) {
          return null;
      }
  
      @Override
      public Set entrySet() {
          return null;
      }

      @Override
      public Set keySet() {
          return null;
      }

      @Override
      public Collection values() {
          return null;
      }

      @Override
      public boolean equals(Object other) {
          return false;
      }

      @Override
      public void clear() {
      }

      @Override
      public void putAll(Map map) {
      }

      @Override
      public boolean containsValue(Object value) {
          return false;
      }
      
      @Override
      public boolean containsKey(Object key) {
          return false;
      }

      @Override
      public boolean isEmpty() {
          return false;
      }

      @Override
      public int size() {
          return 0;
      }
}
