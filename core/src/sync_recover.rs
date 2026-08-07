//! Poison-recovering lock helpers.
//!
//! `std::sync::Mutex` and `RwLock` poison themselves permanently when a thread
//! panics while holding the guard. Every later `.lock().unwrap()` on that lock
//! then panics too, so a single panic anywhere in a request handler takes the
//! process out for good: `CatchPanicLayer` turns each panic into a 500, and the
//! node serves 500s until someone restarts it. The panic is contained; the
//! outage is not.
//!
//! `parking_lot` solves this by not poisoning at all, which is the behaviour
//! these helpers reproduce without a ~570-site type migration: on poison, clear
//! it and take the guard.
//!
//! Ignoring poison means accepting that the protected value may have been
//! observed mid-mutation by the panicking thread. That is exactly the trade
//! `parking_lot` makes and the one this service wants: the alternative is not
//! "consistent state", it is "no service". The values behind these locks are a
//! SQLite connection (an interrupted transaction fails its next statement
//! loudly) and the server state struct.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub trait MutexRecover<T: ?Sized> {
    /// Lock, recovering from a poisoned lock instead of panicking.
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexRecover<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        match self.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

pub trait RwLockRecover<T: ?Sized> {
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T>;
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockRecover<T> for RwLock<T> {
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T> {
        match self.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T> {
        match self.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn poisoned_mutex_still_serves_the_next_caller() {
        let m = Arc::new(Mutex::new(0u32));
        let m2 = Arc::clone(&m);
        // Poison it exactly the way a panicking request handler would.
        let _ = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("handler blew up while holding the lock");
        })
        .join();
        assert!(m.is_poisoned(), "precondition: the lock is poisoned");
        assert!(
            m.lock().is_err(),
            "std lock would fail here — this is the outage"
        );

        *m.lock_or_recover() += 1;
        assert_eq!(*m.lock_or_recover(), 1);
        assert!(
            !m.is_poisoned(),
            "poison cleared, so later callers take the fast path"
        );
    }

    #[test]
    fn poisoned_rwlock_still_serves_readers_and_writers() {
        let l = Arc::new(RwLock::new(String::new()));
        let l2 = Arc::clone(&l);
        let _ = std::thread::spawn(move || {
            let _guard = l2.write().unwrap();
            panic!("handler blew up while holding the write guard");
        })
        .join();
        assert!(l.is_poisoned());

        l.write_or_recover().push_str("still here");
        assert_eq!(&*l.read_or_recover(), "still here");
        assert!(!l.is_poisoned());
    }
}
