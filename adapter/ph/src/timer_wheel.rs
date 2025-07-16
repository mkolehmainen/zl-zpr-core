//! A basic timer wheel.
//!
//! Allows scheduling events at a specified time in the near future.
//!
//! Counts time in quantums out to a specified horizon.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A handle to a scheduled timer wheel event.
///
/// Non-owning.
#[derive(Clone, Copy, Debug)]
pub struct EventHandle {
    when: u64,    // slot relative to elapsed
    index: usize, // index within slot
}

/// A basic timer wheel.
///
/// Note, this struct itself does not interact with the real flow of time.
/// It maintains the schedule relative to its own manually controlled
/// notion of time.
///
/// Most users will want to use this in conjunction with `run()` to
/// actually process events in response to the real flow of time.
pub struct TimerWheel<Ev> {
    // The time of our most recently processed tick.
    now: Instant,
    // The duration of each tick.
    quantum: Duration,
    // How many ticks have elapsed.
    elapsed: u64,
    // The wheel holding our events.  Note, size is at most u32::MAX (our horizon).
    wheel: VecDeque<Vec<Ev>>,
}

impl<Ev> TimerWheel<Ev> {
    /// Create a new `TimerWheel`.
    ///
    /// `quantum` specifies the duration of each tick.
    ///
    /// `horizon` specifies the maximum number of ticks in the future
    /// which an event may be scheduled.  The wheel requires memory
    /// proporitional to this figure.
    ///
    /// `now` specifies the initial notion of "current" time relative to which
    /// events will be scheduled.  Most users will want to specify
    /// `std::time::Instant::now()` here.
    pub fn new(quantum: Duration, horizon: u32, now: Instant) -> Self {
        let mut wheel = VecDeque::with_capacity(horizon as usize);
        for _ in 0..horizon {
            wheel.push_back(Vec::new());
        }

        Self {
            now,
            quantum,
            elapsed: 0,
            wheel,
        }
    }

    /// Schedule an event to occur at the given time.
    ///
    /// The event will not occur before the given time,
    /// but will be delayed up to one quantum after the given time,
    /// and may be delayed further due to scheduling.
    ///
    /// If the time is beyond the wheel's horizon, `Err` is returned
    /// containing the unscheduled event.
    ///
    /// If the time is in the past, the event is scheduled to occur
    /// at the next quantum.  (It will not occur immediately, even if
    /// `tick()` is called immedately.)
    pub fn insert(&mut self, event: Ev, when: Instant) -> Result<EventHandle, Ev> {
        self.insert_after(event, when.saturating_duration_since(self.now))
    }

    /// Schedule an event to occur after the given duration
    /// _relative to the previous tick_.
    ///
    /// If the duration is beyond the wheel's horizon, `Err` is returned
    /// containing the unscheduled event.
    ///
    /// This is primarily useful to precisely re-schedule a recurring event.
    ///
    /// If you wish to schedule an event relative to the current "real" time,
    /// use `insert()` with a time derived from `std::time::Instant::now()`.
    pub fn insert_after(&mut self, event: Ev, after: Duration) -> Result<EventHandle, Ev> {
        self.insert_after_ticks(
            event,
            (after.div_duration_f32(self.quantum).ceil() - 1.0) as u32,
        )
    }

    /// Schedule an event to occur exactly at the given future tick (`slot`),
    /// 0 being the upcoming tick.
    ///
    /// If the tick is beyond the wheel's horizon, `Err` is returned
    /// containing the unscheduled event.
    pub fn insert_after_ticks(&mut self, event: Ev, slot: u32) -> Result<EventHandle, Ev> {
        if slot >= self.wheel.len() as u32 {
            return Err(event);
        }

        let index = self.wheel[slot as usize].len();
        self.wheel[slot as usize].push(event);
        Ok(EventHandle {
            when: self.elapsed.wrapping_add(slot as u64),
            index,
        })
    }

    /// Obtain a reference to the specified event,
    /// if it has not yet been processed.
    pub fn event_ref(&self, hnd: EventHandle) -> Option<&Ev> {
        let slot = hnd.when.wrapping_sub(self.elapsed);

        if slot >= self.wheel.len() as u64 {
            return None;
        }

        Some(&self.wheel[slot as usize][hnd.index])
    }

    /// Obtain a mutable reference to the specified event,
    /// if it has not yet been processed.
    pub fn event_mut(&mut self, hnd: EventHandle) -> Option<&mut Ev> {
        let slot = hnd.when.wrapping_sub(self.elapsed);
        if slot >= self.wheel.len() as u64 {
            return None;
        }

        Some(&mut self.wheel[slot as usize][hnd.index])
    }

    /// Returns the configured tick quantum.
    pub fn quantum(&self) -> Duration {
        self.quantum
    }

    /// Returns the timestamp of the previous (most recently processed) tick.
    pub fn previous_tick(&self) -> Instant {
        self.now
    }

    /// Returns the timestamp of the next (immediately upcoming) tick.
    ///
    /// Notably, this indicates the timestamp after which `tick()` should be invoked.
    pub fn next_tick(&self) -> Instant {
        self.now + self.quantum
    }

    /// Advances the wheel up to the given timestamp.
    ///
    /// For most users, this timestamp should be `std::time::Instant::now()`.
    ///
    /// The wheel will be ticked forward a whole number of quantums to a tick
    /// _no later than_ this timestamp.  (Thus, the wheel's internal notion
    /// of time does not drift, regardless of the rate at which this method
    /// is invoked.)
    ///
    /// All events in these quantums will be returned as an iterator to the caller.
    pub fn tick(&mut self, now: Instant) -> impl Iterator<Item = Ev> + use<'_, Ev> {
        // determine the whole number of quantums elapsed, rounding down
        // note that f32 -> u32 saturates
        let delta = now
            .saturating_duration_since(self.now)
            .div_duration_f32(self.quantum)
            .floor() as u32;

        // advance our notion of time by the whole number of quantums elapsed
        self.now += self.quantum * delta;
        self.elapsed = self.elapsed.wrapping_add(delta as u64);

        // if the delta is greater than the wheel size, just process the full wheel
        let to_process = std::cmp::min(delta, self.wheel.len() as u32);

        // rotate the wheel by the amount we'll be processing
        self.wheel.rotate_left(to_process as usize);

        // drain that now-rotated portion of the wheel to the caller
        self.wheel
            .range_mut(self.wheel.len() - (to_process as usize)..self.wheel.len())
            .map(|it| it.drain(..))
            .flatten()
    }
}

/// Runs the given `TimerWheel` using a flow of time based on
/// `tokio::time::Instant::now()`, and scheduled via Tokio.
///
/// Events which occur will be passed in time order to `process()`.
///
/// All calls to `process()` will occur sequentially in the same task which
/// is executing `run` and therefore should execute "quickly" (i.e., not block
/// or perform significant CPU processing).
///
/// The mutex is _not_ held during calls to `process()`, nor is time advanced.
/// Therefore `process()` may freely interact with the wheel, and `previous_tick()`
/// will always refer to the tick which just occurred.  (However, note that
/// this may not be the tick in which the event was actually scheduled,
/// if this task was delayed resulting in multiple ticks being processed at once.)
///
/// Runs until `ctok` is canceled.
pub async fn run<Ev>(
    wheel: &std::sync::Mutex<TimerWheel<Ev>>,
    process: impl Fn(Ev),
    ctok: tokio_util::sync::CancellationToken,
) {
    let mut next_tick = wheel.lock().unwrap().next_tick();

    loop {
        tokio::select! {
            biased;  // ensure cancellation takes priority

            _ = ctok.cancelled() => break,

            // NOTE: we use `sleep_until()` rather than `Interval` to avoid the issue
            // that the `Interval` drifts slightly and we suddenly introduce a
            // quantum-sized gap in our scheduling.
            _ = tokio::time::sleep_until(next_tick.into()) => {
                let mut locked_wheel = wheel.lock().unwrap();
                // Collect the events so we can drop the lock while processing them.
                let evs: Vec<_> = locked_wheel.tick(tokio::time::Instant::now().into_std()).collect();
                next_tick = locked_wheel.next_tick();
                drop(locked_wheel);
                evs.into_iter().for_each(&process);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{run, TimerWheel};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    const SECOND: Duration = Duration::from_secs(1);
    // used to adjust events slightly before ticks to avoid floating point rounding issues
    const SMIDGE: Duration = Duration::from_millis(100);

    /// Use Tokio's clock as our time base (for testability).
    fn tokio_now() -> Instant {
        tokio::time::Instant::now().into_std()
    }

    #[test]
    fn test_no_events() {
        let now = Instant::now();
        let mut wh: TimerWheel<()> = TimerWheel::new(SECOND, 60, now);
        assert_eq!(wh.tick(now + SECOND).count(), 0);
    }

    #[test]
    fn test_no_tick() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now - SMIDGE).unwrap();
        assert_eq!(wh.tick(now).count(), 0);
    }

    #[test]
    fn test_one_event() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now + SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + SECOND).count(), 1);
        assert_eq!(wh.tick(now + 2 * SECOND).count(), 0);
    }

    #[test]
    fn test_several_events() {
        // tests:
        // * multiple events in one slot
        // * ticks which span multiple slots

        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);

        for i in 0..5 {
            wh.insert(i, now + i * SECOND - SMIDGE).unwrap();
        }

        wh.insert(60, now + 60 * SECOND - SMIDGE).unwrap();

        // note, first tick gets events at T=0 and T=1
        assert_eq!(wh.tick(now + SECOND).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(wh.tick(now + 3 * SECOND).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(wh.tick(now + 5 * SECOND).collect::<Vec<_>>(), vec![4]);
        assert_eq!(wh.tick(now + 60 * SECOND).collect::<Vec<_>>(), vec![60]);
        assert_eq!(wh.tick(now + 61 * SECOND).count(), 0);
    }

    #[test]
    fn test_too_old() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now - SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + SECOND).count(), 1);
    }

    #[test]
    fn test_too_new() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now + 61 * SECOND - SMIDGE).unwrap_err();
    }

    #[test]
    fn test_very_large_tick() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now + SECOND - SMIDGE).unwrap();
        wh.insert((), now + 60 * SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + 100 * SECOND).count(), 2);
    }

    #[test]
    fn test_fractional_tick() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert((), now + SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + Duration::from_millis(200)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(400)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(600)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(800)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(1000)).count(), 1);
        assert_eq!(wh.tick(now + Duration::from_millis(1200)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(1400)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(1600)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(1800)).count(), 0);
        assert_eq!(wh.tick(now + Duration::from_millis(2000)).count(), 0);
    }

    #[test]
    fn test_time_advance() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        wh.insert(123, now + SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + SECOND).collect::<Vec<_>>(), vec![123]);
        wh.insert(456, now + 2 * SECOND - SMIDGE).unwrap();
        assert_eq!(wh.tick(now + 2 * SECOND).collect::<Vec<_>>(), vec![456]);
    }

    #[test]
    fn test_event_refs() {
        let now = Instant::now();
        let mut wh = TimerWheel::new(SECOND, 60, now);
        let ev123 = wh.insert(123, now + SECOND - SMIDGE).unwrap();
        let ev456 = wh.insert(456, now + SECOND - SMIDGE).unwrap();
        let ev789 = wh.insert(789, now + 2 * SECOND - SMIDGE).unwrap();

        assert_eq!(*wh.event_ref(ev123).unwrap(), 123);
        assert_eq!(*wh.event_ref(ev456).unwrap(), 456);
        assert_eq!(*wh.event_ref(ev789).unwrap(), 789);

        *wh.event_mut(ev456).unwrap() = 654;
        assert_eq!(*wh.event_ref(ev456).unwrap(), 654);

        assert_eq!(
            wh.tick(now + 2 * SECOND).collect::<Vec<_>>(),
            vec![123, 654, 789]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_run() {
        let wh = Arc::new(Mutex::new(TimerWheel::new(SECOND, 60, tokio_now())));
        let ctok = CancellationToken::new();
        let (send, mut recv) = mpsc::unbounded_channel();

        let wh_run = wh.clone();
        let wh_ctok = ctok.clone();
        let run_task =
            tokio::spawn(async move { run(&wh_run, |ev| send.send(ev).unwrap(), wh_ctok).await });

        wh.lock()
            .unwrap()
            .insert(123, tokio_now() + SECOND - SMIDGE)
            .unwrap();
        wh.lock()
            .unwrap()
            .insert(456, tokio_now() + SECOND - SMIDGE)
            .unwrap();
        wh.lock()
            .unwrap()
            .insert(789, tokio_now() + 2 * SECOND - SMIDGE)
            .unwrap();

        // First ensure nothing pops out immediately.
        tokio::time::timeout(Duration::from_millis(100), recv.recv())
            .await
            .unwrap_err();

        // Now, we should get the first two items after one second, and no more after that.
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(1100), recv.recv())
                .await
                .unwrap()
                .unwrap(),
            123
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), recv.recv())
                .await
                .unwrap()
                .unwrap(),
            456
        );
        tokio::time::timeout(Duration::from_millis(100), recv.recv())
            .await
            .unwrap_err();

        // Third items should come after another second, and again no more after that.
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(1100), recv.recv())
                .await
                .unwrap()
                .unwrap(),
            789
        );
        tokio::time::timeout(Duration::from_millis(100), recv.recv())
            .await
            .unwrap_err();

        // Test cancellation.
        ctok.cancel();
        tokio::time::timeout(Duration::from_millis(100), run_task)
            .await
            .unwrap()
            .unwrap();
    }
}
