use std::cell::UnsafeCell;
use std::mem::ManuallyDrop;
use std::sync::{atomic::{AtomicU8, Ordering}, Arc, Mutex};

type CslabTable<T> = [UnsafeCell<Entry<T>>];
type CslabBitmap = [AtomicU8];

union Entry<T> {
    next_free: isize,  // offset to next empty; neighbor is 0 so zero-alloced array is initialized
    item: ManuallyDrop<T>,
}

struct CslabShared<T> {
    table: Arc<CslabTable<T>>,
    bitmap: Arc<CslabBitmap>,
}

impl<T> CslabShared<T> {
    pub fn get(&self, idx: usize) -> Option<&T> {
        // check flag
        if (self.bitmap[idx >> 3].load(Ordering::Acquire) >> (idx & 7)) & 1 != 0 {
            // load item
            // SAFETY: the bitmap has told us there is an item
            Some(unsafe { &(*self.table[idx].get()).item })
        } else {
            None
        }
    }
}

impl<T> Clone for CslabShared<T> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            bitmap: self.bitmap.clone(),
        }
    }
}

pub struct CslabReader<T>(CslabShared<T>);

impl<T> CslabReader<T> {
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.0.get(idx)
    }
}

impl<T> Clone for CslabReader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct Cslab<T> {
    capacity: usize,
    first_free: usize, // >= capacity indicates empty freelist
    last_free: usize, // valid only if freelist is not empty
    shared: CslabShared<T>,
}

impl<T> Cslab<T> {
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        let mut table = Vec::with_capacity(capacity);
        table.resize_with(capacity, || UnsafeCell::new(Entry { next_free: 0 }));

        let mut bitmap = Vec::with_capacity(capacity);
        bitmap.resize_with(capacity, || AtomicU8::new(0));

        Self {
            capacity,
            first_free: 0,
            last_free: capacity - 1,
            shared: CslabShared {
                table: table.into_boxed_slice().into(),
                bitmap: bitmap.into_boxed_slice().into(),
            }
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        self.shared.get(idx)
    }

    pub fn reader(&self) -> CslabReader<T> {
        CslabReader(self.shared.clone())
    }

    pub fn insert(&mut self, item: T) -> Result<usize, ()> {
        let idx = self.first_free;

        if idx >= self.capacity {
            return Err(());
        }

        // update freelist
        // SAFETY: any index in the freelist has no item
        self.first_free = (idx as isize + 1 + unsafe { (*self.shared.table[idx].get()).next_free }) as usize;

        // store item
        // SAFETY: any index in the freelist has no item
        unsafe { (*self.shared.table[idx].get()).item = ManuallyDrop::new(item) };

        // mark in bitmap
        let mask = self.shared.bitmap[idx >> 3].load(Ordering::Relaxed);
        debug_assert!((mask >> (idx & 7)) & 1 == 0);
        self.shared.bitmap[idx >> 3].store(mask | (1 << (idx & 7)), Ordering::Release);

        // W:store item -> W:store(Rel) flag -> R:load(Acq) flag -> R:load item

        Ok(idx)
    }

    pub fn mark_removed(&mut self, idx: usize) {
        let mask = self.shared.bitmap[idx >> 3].load(Ordering::Relaxed);

        // confirm we're deleting something that's present
        // (this is really a requirement of `finalize_remove()`
        assert!((mask >> (idx & 7)) & 1 == 1);

        // mark the item as free (but don't actually free it)
        self.shared.bitmap[idx >> 3].store(mask & !(1 << (idx & 7)), Ordering::Relaxed);

        // W:store(Rlx) flag -> W:update(Rel) -> R:update(Acq) -> R:load(Rlx) flag
        // R:update(Acq) -> R:sync(Rel)
        // R:load item -> R:sync(Rel) -> W:sync(Acq) -> W:delete item
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
        let mask = self.shared.bitmap[idx >> 3].load(Ordering::Relaxed);
        assert!((mask >> (idx & 7)) & 1 == 0);

        // drop item
        // SAFETY: we know only we can access this item from our safety requirement
        let entry = &mut *self.shared.table[idx].get();
        // SAFETY: we know there is an item from our safety requirement
        let item = unsafe { ManuallyDrop::take(&mut entry.item) };

        // add entry to end of freelist
        // SAFETY: we have removed the item
        entry.next_free = (self.capacity - idx) as isize - 1;

        if self.first_free < self.capacity {
            // freelist was non-empty, update final entry
            // SAFETY: any index in the freelist has no item
            unsafe { (*self.shared.table[self.last_free].get()).next_free =
                idx as isize - self.last_free as isize; }
        } else {
            // freelist was empty, update head pointer
            self.first_free = idx;
        }

        self.last_free = idx;

        item
    }
}

// NOTE: it is unsafe to allow arbitrary `CslabReader`s to be cloned
// from an `RcuCslab`!  Our internal safety guarantees rely on
// accesses being performed _only_ through the `RcuCslab`.

pub struct RcuCslab<T> {	
    capacity: usize,
    writer: Arc<Mutex<Cslab<T>>>,
    reader: CslabReader<T>,
    pending_removes: Mutex<Vec<usize>>,  // FIXME: repalce with SyncUnsafeCell; we are always holding the writer mutex
}

impl<T> RcuCslab<T> {
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        let cslab = Cslab::with_fixed_capacity(capacity);
        let reader = cslab.reader();
        Self {
            capacity: cslab.capacity(),
            writer: Arc::new(Mutex::new(cslab)),
            reader,
            pending_removes: Mutex::new(Vec::new()),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        self.reader.get(idx)
    }

    pub fn insert(&self, item: T) -> Result<usize, ()> {
        self.writer.lock().unwrap().insert(item)
    }

    pub fn remove(&self, idx: usize) {
        let mut writer = self.writer.lock().unwrap();
        let mut pending_removes = self.pending_removes.lock().unwrap();
        writer.mark_removed(idx);
        pending_removes.push(idx);
    }
}

// FIXME: we need to DISALLOW anyone but the "writer" from removing stuff!
// only one writer can be removing things!!

// FIXME: we need to somehow prevent OUT-OF-ORDER cleanups!!
// either prevent having multiple read versions,
// or somehow ensure they're cleaned in order...
// older one holds reference to newer one???

impl<T> Clone for RcuCslab<T> {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            writer: self.writer.clone(),
            reader: self.reader.clone(),
            pending_removes: Mutex::new(Vec::new()),
        }
    }
}

impl<T> Drop for RcuCslab<T> {
    fn drop(&mut self) {
        let pending_drops: Box<[_]> = {
            let mut writer = self.writer.lock().unwrap();
            // SAFETY: all items in pending_removes have been marked
            // SAFETY: being RCU-dropped means we have synchronized with the writer
            self.pending_removes.get_mut().unwrap().iter().map(|&idx|
                unsafe { writer.finalize_remove(idx) }).collect()
        };

        // drop items outside the mutex to prevent deadlocks
        std::mem::drop(pending_drops);
    }
}
