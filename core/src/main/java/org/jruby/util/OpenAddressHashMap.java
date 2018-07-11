package org.jruby.util;

import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.util.Collection;

import org.jruby.ObjectFlags;
import org.jruby.runtime.builtin.IRubyObject;

public class OpenAddressHashMap {
      private static final int HASH_SIGN_BIT_MASK = ~(1 << 31);
      public IRubyObject[] entries;
      private int[] bins;
      private int size;
      private int length;
      private final static int EMPTY_BIN = -1;
      private final static int DELETED_BIN = -2;
      private final static int A = 5;
      private final static int C = 1;
      public static final int COMPARE_BY_IDENTITY_F = ObjectFlags.COMPARE_BY_IDENTITY_F;
      private final static int ENTRIES_PER_PAIR = 2;
      private int generation = 0; // generation count for O(1) clears

      public OpenAddressHashMap() {
          this(16);
      }

      public OpenAddressHashMap(int length) {
          this.length = length;
          entries = new IRubyObject[length * ENTRIES_PER_PAIR];
          bins = new int[length * ENTRIES_PER_PAIR];
          Arrays.fill(bins, EMPTY_BIN);
          size = 0;
      }
      
      public final void checkResize(int flags) {
          if (entries.length == size * ENTRIES_PER_PAIR) {
              resize(entries.length << 1, flags);
              return;
          }
          return;
      }
      
      public final synchronized void resize(int newCapacity, int flags) {
        final IRubyObject[] oldTable = entries;
        final IRubyObject[] newTable = new IRubyObject[newCapacity];
        final int[] newBins = new int[newCapacity];
        Arrays.fill(newBins, EMPTY_BIN);
        IRubyObject key, value;
        int index, bin, hash;

        for (int i = 0; i < oldTable.length; i += 2) {
          key = oldTable[i];
          value = oldTable[i + 1];
          newTable[i] = key;
          newTable[i + 1] = value;

          if (key == null)
              break;

          hash = hashValue(key, flags);
          bin = bucketIndex(hash, newBins.length);
          index = newBins[bin];

          while(index != EMPTY_BIN) {
            bin = secondaryBucketIndex(bin, newBins.length);
            index = newBins[bin];
          }
          newBins[bin] = i;
        }

        bins = newBins;
        entries = newTable;
      }

      protected final int hashValue(final Object key, int flags) {
          final int h = isComparedByIdentity(flags) ? System.identityHashCode(key) : key.hashCode();
          return h & HASH_SIGN_BIT_MASK;
      }

      private static int bucketIndex(final int h, final int length) {
          return h & (length - 1);
      }

      private boolean internalKeyExist(IRubyObject key, IRubyObject otherKey, int flags) {
          return (key == otherKey || (!isComparedByIdentity(flags) && key.eql(otherKey)));
      }

      protected boolean isComparedByIdentity(int flags) {
          return (flags & COMPARE_BY_IDENTITY_F) != 0;
      }

      private static int secondaryBucketIndex(final int bucketIndex, final int length) {
        return (A * bucketIndex + C) & (length - 1);
      }

      public IRubyObject putIndex(int index, IRubyObject value) {
          IRubyObject tmp = entries[index + 1];
          entries[index + 1] = value;
          return tmp;
      }

      public void putNoResize(IRubyObject key, IRubyObject value, int flags) {
          final int hash = hashValue(key, flags);
          int bin = bucketIndex(hash, bins.length);
          int index = bins[bin];
          IRubyObject otherKey;

          entries[size * ENTRIES_PER_PAIR] = key;
          entries[size * ENTRIES_PER_PAIR + 1] = value;
          while(index != EMPTY_BIN && index != DELETED_BIN) {
              bin = secondaryBucketIndex(bin, bins.length);
              index = bins[bin];
          }
          bins[bin] = size * ENTRIES_PER_PAIR;
          size++;
      }

      public int getIndex(IRubyObject key, int flags) {
          if (isEmpty())
              return EMPTY_BIN;

          final int hash = hashValue(key, flags);
          int bin = bucketIndex(hash, bins.length);
          int index = bins[bin];
          IRubyObject otherKey;

          while(index != EMPTY_BIN && index != DELETED_BIN) {
              otherKey = entries[index];
              if (internalKeyExist(key, otherKey, flags)) {
                  return index;
              }
              bin = secondaryBucketIndex(bin, bins.length);
              index = bins[bin];
          }

          return EMPTY_BIN;
      }
      
      public IRubyObject deleteKey(final IRubyObject otherKey, int flags) {
          if (isEmpty()) return null;

          final int hash = hashValue(otherKey, flags);
          int bin = bucketIndex(hash, bins.length);
          int index = bins[bin];
          IRubyObject key, value;

          while (index != EMPTY_BIN) {
              if (index != DELETED_BIN) {
                  key = entries[index];
                  value = entries[index + 1];
                  // TODO is this correct?
                  if (key == otherKey) {
                    bins[bin] = DELETED_BIN;
                    entries[index] = null;
                    entries[index + 1] = null;
                    size--;
                    return value;
                  }  
              }
              bin = secondaryBucketIndex(bin, bins.length);
              index = bins[bin];
          }

          return null;
      }
      
      
      public IRubyObject deleteEntry(final IRubyObject otherKey, final IRubyObject otherValue, int flags) {
          if (isEmpty()) return null;

          final int hash = hashValue(otherKey, flags);
          int bin = bucketIndex(hash, bins.length);
          int index = bins[bin];
          IRubyObject key, value;

          while (index != EMPTY_BIN) {
              if (index != DELETED_BIN) {
                  key = entries[index];
                  value = entries[index + 1];
                  // TODO is this correct?
                  if (key == otherKey && value == otherValue) {
                    bins[bin] = DELETED_BIN;
                    entries[index] = null;
                    entries[index + 1] = null;
                    size--;
                    return value;
                  }  
              }
              bin = secondaryBucketIndex(bin, bins.length);
              index = bins[bin];
          }

          return null;
      }

      public IRubyObject getKey(int index) {
          if (index == EMPTY_BIN)
            return null;
          return entries[index];
      }

      public IRubyObject getValue(int index) {
          if (index == EMPTY_BIN)
            return null;
          return entries[index + 1];
      }
      
      public int getSize() {
          return size;
      }
      
      public boolean is_empty() {
          return size == 0;
      }

      public class BaseIterator implements Iterator {
          final private EntryView view;
          private int index;
          private IRubyObject result;
          private int startGeneration;

          public BaseIterator(EntryView view) {
              this.view = view;
              this.startGeneration = generation;
              index = 0;
          }

          @Override
          public Object next() {
              if (index >= size())
                throw new NoSuchElementException();
              key = entries[index];
              value = entries[index + 1];
              while (key == null && size() > index) {
                  index++;
                  key = entries[index];
                  value = entries[index + 1];
              }
              result = view.convertEntry(key, value);
              index++;
              return result;
          }

          @Override
          public boolean hasNext() {
            if (isEmpty())
                return false;
            if (generation != startGeneration)
                index = 0;
            return size() == index; 
          }

          @Override
          public void remove() {
              if (index >= size())
                throw new IllegalStateException("Iterator out of range");
              deleteEntry(entries[index], entries[index + 1]);
          }
      }

      public <T> void visitAll(ThreadContext context, VisitorWithState visitor, T state) {
          // use -1 to disable concurrency checks
          visitLimited(context, visitor, -1, state);
      }

      public <T> void visitLimited(ThreadContext context, VisitorWithState visitor, long size, T state) {
          int startGeneration = generation;
          long count = size;
          int index = 0;
          IRubyObject key, value;
          for (int i = 0; i < internalMap.entries.length; i += 2) {
              key = entries[i];
              value = entries[i + 1];
              if (key != null) {
                  visitor.visit(context, this, key, value, index++, state);
                  count--;
              }
          }

          // it does not handle all concurrent modification cases,
          // but at least provides correct marshal as we have exactly size entries visited (count == 0)
          // or if count < 0 - skipped concurrent modification checks
          if (count > 0) throw concurrentModification();
      }

      private final RaiseException concurrentModification() {
          return getRuntime().newConcurrencyError(
                  "Detected invalid hash contents due to unsynchronized modifications with concurrent users");
      }
}
