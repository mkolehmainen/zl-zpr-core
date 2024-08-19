//! An RCU-friendly concurrent slab

#[cfg(loom)]
use loom::alloc::{self, Layout};
#[cfg(not(loom))]
use std::alloc::{self, Layout};
//#[cfg(not(loom))]
use std::cell::UnsafeCell;
//#[cfg(loom)]
//use loom::cell::UnsafeCell;
#[cfg(loom)]
use loom::sync;
use std::mem::ManuallyDrop;
#[cfg(not(loom))]
use std::sync;
use sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

// DESIGN NOTES
//
// The slab itself is a traditional freelist design: an allocated
// entry simply contains the item stored at that location; a free
// entry simply contains a pointer to the next free slot.  The only
// addition to this structure is a bitmap we use to allow querying for
// whether an item is present in a given slot.
//
// The complexity of the remainder of the design springs from the goal
// to allow readers to operate concurrently with a writer, while
// maintaining near-zero-cost lookups for readers.
//
// There are only three core operations on an active slab: insert [I],
// remove [R], and get [G] (which notably returns a reference, not a copy).
// A slab may also of course be dropped [D] at the end of its lifetime.
//
// Dropping is enforced by the Rust runtime to only occur once all
// references to the slab have disappeared.  Therefore it can only
// execute exclusively of any other operation.
//
// Since writers can be "slow", we assume a single writer (enforced
// by requiring a mut reference).  Therefore, insert [I] and remove [R]
// execute exclusive of each other.
//
// Get [G] however, may execute concurrently with any other operation.
// Notably, we provide a method `reader()` to obtain a "reader" handle
// which allows performing get [G] operations concurrently with insert [I]
// and remove [R].
//
// Therefore, the concurrency stories we must consider are [I] with [G],
// and [R] with [G].
//
// Insert [I] with get [G] is straightforward.  We require that [I] first
// store the item itself in the slab, _then_ mark the item as present in the
// bitmap.  [G] must likewise first check the bitmap _before_ attempting to
// read an item.  The cross-thread ordering is enforced by a release-acquire
// operation pair on the bitmap element:
//
//          WRITER             |        READER
//                             |
//   store item [Ii]           |
//        ↓                    |
//   store flag [Ib] (release) |
//                             ⇘
//                             | (acquire) load flag [Gb]
//                             |               ↓
//                             |           load item [Gi]
//
// (as marked in the source code).
//
// The complex case is remove [R] with get [G].  The key issue is that a
// writer may wish to remove an item from the slab while a reader is still
// accessing it.  One approach to prevent this would be to have the reader,
// while accessing the item, recheck the flag before any operation which
// would be potentially unsafe in the case that corrupt data had been read.
// This however is intrusive for complex items and suffers from the A/B/A
// problem.
//
// So instead, we follow a model informed by the read-copy-update (RCU)
// family of algorithms.  Remove [R] is split into two phases:
// `mark_removed()`, and `finalize_remove()`.  Both must be performed in
// sequence to remove any item.  Marking may be performed at any time.
// Finalizing however, may only be performed after synchronizing with the
// reader(s) to ensure that no accesses to that item are outstanding.  This
// corresponds directly with the notion of RCU synchronization, in which a
// "cleanup" operation can be scheduled to run after all active read-side
// critical sections have completed.
//
// `mark_removed()` then, simply clears the item's mark in the bitmap.  Get
// [G] operations may safely race this.  They will safely return either the
// item (which has not yet actually been deleted from slab storage), or a
// not found indication.  The writer then must signal the reader(s) that it
// is waiting for all outstanding read-side critical sections to complete
// (this would be e.g.  an RCU update operation).  This signal is
// effectively a release-acquire pair, after which all readers will
// henceforth read the item's bitmap mark clear (and return not found).
//
// The reader(s) then must signal the writer when their outstanding
// read-side critical sections have completed (this would be e.g.  an RCU
// synchronization callback).  This signal again is effectively a
// release-acquire pair.  It's now known to the writer that no reader
// remains accessing the marked item.  `finalize_remove()` may then be
// called, and the item is actually deleted, and the slot returned to the
// slab's freelist.
//
// This complex ordering is illustrated as follows:
//
//        WRITER            |       READER
//                          |
//     store flag [Rb]      |    load flag [Gb]  }
//          ↓               |         ↓          } any number; safely races writer
//     RCU update (release) |   ?load item [Gi]  }
//                          ⇘      |
//                          | (acquire) RCU update
//                          |      ↓  ↓  |
//                          | (release) RCU callback
//                          ⇙            ↓
//   RCU callback (acquire) |    load flag [Gb]  } now reads as clear
//          ↓               |
//    delete item [Ri]      |
//
// Of course, it's critical for writers to correctly track the visibility of
// remove [R] operations to readers.  The `Cslab` data structure does not
// provide this.  Instead, the `RcuCslab` data structure builds upon `Cslab`
// to provide this functionality.  It is described below.

union Entry<T> {
    next_free: isize, // offset to next empty; neighbor is 0 so zero-alloced array is initialized
    item: ManuallyDrop<T>,
}

type CslabTable<T> = [UnsafeCell<Entry<T>>];
type CslabBitmap = [AtomicUsize];

// `CslabStorage` "glues together" the table and bitmap allocations into one.
// This allows us to write a `Drop` implementation which uses both of them.
struct CslabStorage<T> {
    size: usize,
    ptr: *mut u8,
    bitmap_offset: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T> CslabStorage<T> {
    fn table_layout(n: usize) -> Layout {
        Layout::array::<<usize as std::slice::SliceIndex<CslabTable<T>>>::Output>(n).unwrap()
    }

    fn bitmap_layout(n: usize) -> Layout {
        Layout::array::<<usize as std::slice::SliceIndex<CslabBitmap>>::Output>(
            (n + usize::BITS as usize - 1) / usize::BITS as usize,
        )
        .unwrap()
    }

    fn storage_layout(n: usize) -> (Layout, usize) {
        Self::table_layout(n)
            .extend(Self::bitmap_layout(n))
            .unwrap()
    }

    pub fn with_fixed_capacity(size: usize) -> Self {
        assert!(size > 0);

        let (layout, bitmap_offset) = Self::storage_layout(size);

        // SAFETY: layout is not 0-sized
        let ptr = unsafe { alloc::alloc_zeroed(layout) };

        #[cfg(loom)]
        {
            let bitmap: &mut [std::mem::MaybeUninit<AtomicUsize>] = unsafe {
                std::slice::from_raw_parts_mut(
                    ptr.add(bitmap_offset).cast(),
                    (size + usize::BITS as usize - 1) / usize::BITS as usize,
                )
            };
            for bme in bitmap {
                bme.write(AtomicUsize::new(0));
            }
        }

        Self {
            size,
            ptr,
            bitmap_offset,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn table(&self) -> &CslabTable<T> {
        // SAFETY: we've correctly allocated memory
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.size) }
    }

    pub fn bitmap(&self) -> &CslabBitmap {
        // SAFETY: we've correctly allocated memory
        unsafe {
            std::slice::from_raw_parts(
                self.ptr.add(self.bitmap_offset).cast(),
                (self.size + usize::BITS as usize - 1) / usize::BITS as usize,
            )
        }
    }

    pub fn parts_mut(&mut self) -> (&mut CslabTable<T>, &mut CslabBitmap) {
        // SAFETY: we've correctly allocated memory
        (
            unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.size) },
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.ptr.add(self.bitmap_offset).cast(),
                    (self.size + usize::BITS as usize - 1) / usize::BITS as usize,
                )
            },
        )
    }
}

impl<T> Drop for CslabStorage<T> {
    fn drop(&mut self) {
        // FIXME: this is inefficient for very large tables
        // NOTE: we can (a) use bitscanning, and (b) keep a count of how many values remaining

        let size = self.size;
        let (table, bitmap) = self.parts_mut();

        for (i, bme) in bitmap.iter().enumerate() {
            let x = bme.load(Ordering::Relaxed);
            for j in 0..usize::BITS as usize {
                let idx = (i * usize::BITS as usize) + j;
                if idx >= size {
                    break;
                }
                if (x >> j) & 1 != 0 {
                    // SAFETY: we know an element is present from the bit being set
                    // and our requirement that `finalize_remove()` be called
                    // for every `mark_removed()`
                    unsafe { ManuallyDrop::drop(&mut (*table[idx].get()).item) }
                }
            }
        }

        let (layout, _) = Self::storage_layout(self.size);
        // SAFETY: we are dropping; no-one else has a pointer to this
        unsafe {
            alloc::dealloc(self.ptr, layout);
        }
    }
}

fn get_impl<T>(storage: &CslabStorage<T>, idx: usize) -> Option<&T> {
    if idx >= storage.len() {
        return None;
    }

    // check flag
    if (storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Acquire) /* [Gb] */
        >> (idx % usize::BITS as usize))
        & 1
        != 0
    {
        // load item
        // SAFETY: the bitmap has told us there is an item
        Some(unsafe { &(*storage.table()[idx].get()).item }) /* [Gi] */
    } else {
        None
    }
}

/// Cloneable read-only interface to a `Cslab`.
pub struct CslabReader<T>(Arc<CslabStorage<T>>);

impl<T> CslabReader<T> {
    pub fn get(&self, idx: usize) -> Option<&T> {
        get_impl(&*self.0, idx)
    }
}

impl<T> Clone for CslabReader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct Cslab<T> {
    first_free: usize, // >= capacity indicates empty freelist
    in_use: usize,
    allocated: usize,
    storage: Arc<CslabStorage<T>>,
}

impl<T> Cslab<T> {
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        Self {
            first_free: 0,
            in_use: 0,
            allocated: 0,
            storage: Arc::new(CslabStorage::with_fixed_capacity(capacity)),
        }
    }

    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    pub fn len(&self) -> usize {
        self.in_use
    }

    pub fn allocated(&self) -> usize {
        self.allocated
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        get_impl(&*self.storage, idx)
    }

    pub fn reader(&self) -> CslabReader<T> {
        CslabReader(self.storage.clone())
    }

    pub fn insert(&mut self, item: T) -> Result<usize, ()> {
        let idx = self.first_free;

        if idx >= self.storage.table().len() {
            return Err(());
        }

        // update freelist
        // SAFETY: any index in the freelist has no item
        self.first_free =
            (idx as isize + 1 + unsafe { (*self.storage.table()[idx].get()).next_free }) as usize;

        // store item
        // SAFETY: any index in the freelist has no item
        unsafe { (*self.storage.table()[idx].get()).item = ManuallyDrop::new(item) } /* [Ii] */;

        // mark in bitmap
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);
        debug_assert!((mask >> (idx % usize::BITS as usize)) & 1 == 0);
        self.storage.bitmap()[idx / usize::BITS as usize].store(
            mask | (1 << (idx % usize::BITS as usize)),
            Ordering::Release,
        ) /* [Ib] */;

        self.in_use += 1;
        self.allocated += 1;

        Ok(idx)
    }

    /// # Safety
    ///
    /// The item must eventually be removed with `finalize_remove()`.
    pub unsafe fn mark_removed(&mut self, idx: usize) {
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);

        // confirm we're deleting something that's present
        // (this is really a requirement of `finalize_remove()`
        assert!((mask >> (idx % usize::BITS as usize)) & 1 == 1);

        // mark the item as free (but don't actually free it)
        self.storage.bitmap()[idx / usize::BITS as usize].store(
            mask & !(1 << (idx % usize::BITS as usize)),
            Ordering::Relaxed,
        ) /* [Rb] */;

        // W:store(Rlx) flag -> W:update(Rel) -> R:update(Acq) -> R:load(Rlx) flag
        // R:update(Acq) -> R:sync(Rel)
        // R:load item -> R:sync(Rel) -> W:sync(Acq) -> W:delete item

        self.in_use -= 1;
    }

    /// Actually free an index which has been marked free with `mark_removed()`.
    ///
    /// # Safety
    ///
    /// `mark_removed()` must first have been called.  (It is an undetectable
    /// error to call this on an already-freed item.)
    ///
    /// It must be known that there will be no further reads of this index.
    /// This can be guaranteed after calling `mark_removed()` by notifying all
    /// readers of this update, then waiting for all readers to acknowledge
    /// this notification.
    pub unsafe fn finalize_remove(&mut self, idx: usize) -> T {
        // confirm item is not visible
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);
        assert!((mask >> (idx % usize::BITS as usize)) & 1 == 0);

        // drop item
        // SAFETY: we know only we can access this item from our safety requirement
        let entry = &mut *self.storage.table()[idx].get();
        // SAFETY: we know there is an item from our safety requirement
        let item = unsafe { ManuallyDrop::take(&mut entry.item) } /* [Ri] */;

        // add entry to front of freelist
        // SAFETY: we have removed the item
        entry.next_free = self.first_free as isize - idx as isize;
        self.first_free = idx;

        self.allocated -= 1;

        item
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn basic_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        let i = slab.insert(123).unwrap();
        let j = slab.insert(456).unwrap();
        assert_eq!(slab.capacity(), 4);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.allocated(), 2);
        assert_eq!(*slab.get(i).unwrap(), 123);
        assert_eq!(*slab.get(j).unwrap(), 456);
        assert_eq!(slab.get(j + 1), None);
        assert_eq!(slab.get(slab.capacity()), None);
        assert_eq!(slab.get(usize::MAX), None);
    }

    #[test]
    fn at_capacity_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        slab.insert(123).unwrap();
        slab.insert(456).unwrap();
        slab.insert(234).unwrap();
        slab.insert(567).unwrap();
        slab.insert(345).unwrap_err();
        assert_eq!(slab.len(), 4);
        assert_eq!(slab.allocated(), 4);
    }

    #[test]
    fn removal_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let i = slab.insert(123).unwrap();
        let j = slab.insert(456).unwrap();
        unsafe {
            slab.mark_removed(i);
        }
        assert_eq!(slab.get(i), None);
        assert_eq!(*slab.get(j).unwrap(), 456);
        assert_ne!(slab.insert(234).unwrap(), i);
        assert_ne!(slab.insert(567).unwrap(), i);
        slab.insert(345).unwrap_err();
        assert_eq!(unsafe { slab.finalize_remove(i) }, 123);
        let ii = slab.insert(345).unwrap();
        assert_eq!(ii, i);
        assert_eq!(*slab.get(ii).unwrap(), 345);
    }

    #[test]
    fn reader_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        let i = slab.insert(123).unwrap();
        let reader = slab.reader();
        let j = slab.insert(456).unwrap();
        let clone = reader.clone();
        assert_eq!(*reader.get(i).unwrap(), 123);
        assert_eq!(*reader.get(j).unwrap(), 456);
        assert_eq!(*clone.get(i).unwrap(), 123);
        assert_eq!(*clone.get(j).unwrap(), 456);
    }

    struct OnDrop<'a>(&'a dyn Fn());
    impl Drop for OnDrop<'_> {
        fn drop(&mut self) {
            self.0();
        }
    }

    #[test]
    fn removal_drop_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let dropped = std::cell::Cell::new(false);
        let dropper = || assert!(!dropped.replace(true));
        let i = slab.insert(OnDrop(&dropper)).unwrap();
        unsafe {
            slab.mark_removed(i);
        }
        assert!(!dropped.get());
        let item = unsafe { slab.finalize_remove(i) };
        assert!(!dropped.get());
        std::mem::drop(item);
        assert!(dropped.get());
        std::mem::drop(slab);
    }

    #[test]
    fn container_drop_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let i_dropped = std::cell::Cell::new(false);
        let j_dropped = std::cell::Cell::new(false);
        let i_dropper = || assert!(!i_dropped.replace(true));
        let j_dropper = || assert!(!j_dropped.replace(true));
        let i = slab.insert(OnDrop(&i_dropper)).unwrap();
        slab.insert(OnDrop(&j_dropper)).unwrap();
        unsafe {
            slab.mark_removed(i);
            slab.finalize_remove(i);
        }
        assert!(i_dropped.get());
        std::mem::drop(slab);
        assert!(j_dropped.get());
    }
}

#[cfg(all(test, loom))]
mod tests {
    // NOTE: `loom` (and the similar `shuttle` is VERY limited for testing
    // atomic interactions.  Notably, they assume that atomic operations
    // occur _in the order they are issued_, which means they don't test
    // _any_ reorderings in a single-writer/single-reader interaction.

    use super::*;
    use loom::{model, thread};

    #[test]
    fn concurrent_insert_get_test() {
        model(|| {
            let mut slab = Cslab::with_fixed_capacity(4);

            let reader = slab.reader();
            thread::spawn(move || match reader.get(0) {
                Some(&x) => assert_eq!(x, 123),
                None => (),
            });

            slab.insert(123).unwrap();
        });
    }

    #[test]
    fn concurrent_remove_get_test() {
        model(|| {
            let mut slab = Cslab::with_fixed_capacity(4);

            let idx = slab.insert(123).unwrap();

            let reader = slab.reader();
            let t1 = thread::spawn(move || match reader.get(idx) {
                Some(&x) => assert_eq!(x, 123),
                None => (),
            });

            unsafe {
                slab.mark_removed(idx);
            }

            t1.join().unwrap();

            let reader = slab.reader();
            thread::spawn(move || {
                assert_eq!(reader.get(idx), None);
            });

            unsafe {
                slab.finalize_remove(idx);
            }
        });
    }
}

// NOTE: it is unsafe to allow arbitrary `CslabReader`s to be cloned
// from an `RcuCslab`!  Our internal safety guarantees rely on
// accesses being performed _only_ through the `RcuCslab`.

struct RcuCslabGenInner<T> {
    // list of indexes whose removal we can finalize once this generation
    // is dropped (since all future active generations will have read the removal mark)
    pending_removes: Vec<usize>,

    // a reference count used to prevent newer generations from
    // being collected before older generations
    next_gen: Option<Arc<RcuCslabGen<T>>>,
}

struct RcuCslabGen<T> {
    // a reference to the writer, used to perform removal finalization
    writer: Arc<Mutex<Cslab<T>>>,

    // the actual generation info, protected by a mutex
    inner: Mutex<RcuCslabGenInner<T>>,
}

impl<T> Drop for RcuCslabGen<T> {
    fn drop(&mut self) {
        let pending_drops: Box<[_]> = {
            let mut writer = self.writer.lock().unwrap();
            // SAFETY: all items in pending_removes have been marked
            // SAFETY: being RCU-dropped means we have synchronized with the writer
            self.inner
                .get_mut()
                .unwrap()
                .pending_removes
                .iter()
                .map(|&idx| unsafe { writer.finalize_remove(idx) })
                .collect()
        };

        // drop items outside the mutex to prevent deadlocks
        std::mem::drop(pending_drops);
    }
}

pub struct RcuCslabReader<T> {
    // unsynchronized read access to the slab
    reader: CslabReader<T>,

    // reference to the generation we were created in
    gen: Arc<RcuCslabGen<T>>,
}

impl<T> RcuCslabReader<T> {
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.reader.get(idx)
    }
}

impl<T> Clone for RcuCslabReader<T> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            gen: self.gen.clone(),
        }
    }
}

pub struct RcuCslab<T> {
    // unsynchronized access to capacity
    capacity: usize,

    // main reference to the writer
    writer: Arc<Mutex<Cslab<T>>>,

    // an unsynchronized reader we can clone cheaply
    reader: CslabReader<T>,

    // reference to the current generation of readers
    cur_gen: Arc<RcuCslabGen<T>>,
}

impl<T> RcuCslab<T> {
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        let cslab = Cslab::with_fixed_capacity(capacity);
        let reader = cslab.reader();
        let writer = Arc::new(Mutex::new(cslab));
        let cur_gen = Arc::new(RcuCslabGen {
            writer: writer.clone(),
            inner: Mutex::new(RcuCslabGenInner {
                pending_removes: Vec::new(),
                next_gen: None,
            }),
        });

        Self {
            capacity,
            writer,
            reader,
            cur_gen,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.writer.lock().unwrap().len()
    }

    pub fn allocated(&self) -> usize {
        self.writer.lock().unwrap().allocated()
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        self.reader.get(idx)
    }

    pub fn reader(&self) -> RcuCslabReader<T> {
        RcuCslabReader {
            reader: self.reader.clone(),
            gen: self.cur_gen.clone(),
        }
    }

    // NOTE: it's a happy accident of the implementation that `insert()` and
    // `remove()` become non-mut.  I don't see a downside and it's convenient.

    pub fn insert(&self, item: T) -> Result<usize, ()> {
        self.writer.lock().unwrap().insert(item)
    }

    pub fn remove(&self, idx: usize) {
        // NOTE: order here doesn't matter; no-one will do anything with
        // `pending_removes` until `collect()` (which is mut) releases the references
        // to `cur_gen`
        // SAFETY: we eventually call `finalize_remove()` on drop
        unsafe {
            self.writer.lock().unwrap().mark_removed(idx);
        }
        self.cur_gen.inner.lock().unwrap().pending_removes.push(idx);
    }

    pub fn collect(&mut self) {
        let next_gen = Arc::new(RcuCslabGen {
            writer: self.writer.clone(),
            inner: Mutex::new(RcuCslabGenInner {
                pending_removes: Vec::new(),
                next_gen: None,
            }),
        });

        {
            let mut cur_gen_inner = self.cur_gen.inner.lock().unwrap();
            debug_assert!(cur_gen_inner.next_gen.is_none());
            cur_gen_inner.next_gen = Some(next_gen.clone());
        }

        self.cur_gen = next_gen;
    }
}
