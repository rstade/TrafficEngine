use std::clone::Clone;
use std::vec::Drain;
use std::cmp::min;
use std::fmt::Debug;
use e2d2::utils;
//use separator::Separatable;

// TODO retrieve this system constant from Linux
pub const MILLIS_TO_CYCLES: u64 = 2270000u64;

/*
pub fn duration_to_millis(dur: &Duration) -> u64 {
    dur.as_secs() * 1000 + (dur.subsec_nanos() / 1000000) as u64
}

pub fn duration_to_micros(dur: &Duration) -> u64 {
    dur.as_secs() * 1000 * 1000 + (dur.subsec_nanos() / 1000) as u64
}

*/

pub struct TimerWheel<T>
where
    T: Clone,
{
    resolution_cycles: u64,
    no_slots: usize,
    last_slot: usize,  // slot which was drained at the last tick
    last_advance: u64, // number of slots drained since start
    start: u64,        // time when wheel started
    slots: Vec<Vec<T>>,
}

#[allow(dead_code)]
impl<T> TimerWheel<T>
where
    T: Clone,
{
    pub fn new(no_slots: usize, resolution_cycles: u64, slot_capacity: usize) -> TimerWheel<T> {
        //let now = utils::rdtsc_unsafe();
        //println!("wheel start = {:?}", now);
        TimerWheel {
            resolution_cycles,
            no_slots,
            last_slot: no_slots - 1,
            last_advance: 0,
            //start: now - resolution_cycles,
            start: 0,
            slots: vec![Vec::with_capacity(slot_capacity); no_slots],
        }
    }

    pub fn resolution(&self) -> u64 {
        self.resolution_cycles
    }

    pub fn get_max_timeout_cycles(&self) -> u64 {
        (self.no_slots as u64 - 1) * self.resolution_cycles as u64
    }

    #[inline]
    pub fn tick(&mut self, now: &u64) -> (Option<Drain<T>>, bool) {
        if self.start != 0 { // only when the wheel has been started
            let dur = *now - self.start;
            let advance = dur / self.resolution_cycles;
            //trace!("dur= {:?}, advance= {}, last_advance= {}", dur, advance, self.last_advance);
            let progress = (advance - self.last_advance) as usize;
            let mut slots_to_process = min(progress, self.no_slots);
            if progress > self.no_slots {
                self.last_slot = (advance - slots_to_process as u64).wrapping_rem(self.no_slots as u64) as usize;
                self.last_advance = advance - slots_to_process as u64;
            }
            while slots_to_process > 0 {
                self.last_slot = (self.last_slot + 1).wrapping_rem(self.no_slots);
                self.last_advance += 1;
                if self.slots[self.last_slot].len() > 0 {
                    debug!(
                        "slots_to_process= {}, processing slot {} with {} events",
                        slots_to_process,
                        self.last_slot,
                        self.slots[self.last_slot].len()
                    );
                    return (Some(self.slots[self.last_slot].drain(..)), slots_to_process > 1);
                } else {
                    slots_to_process -= 1
                }
            }
        }
        (None, false)
    }

    #[inline]
    pub fn schedule(&mut self, after_cycles: &u64, what: T) -> u64
    where
        T: Debug,
    {
        let now=utils::rdtsc_unsafe();
        if self.start==0 { self.start=now-self.resolution_cycles; } //initialize start time
        let dur = *after_cycles +  now - self.start;
        let slots= dur/self.resolution_cycles-1;
        let slot = slots.wrapping_rem(self.no_slots as u64);
        //debug!("scheduling port {:?} at {:?} in slot {}", what, when.separated_string(), slot);
        self.slots[slot as usize].push(what);
        slot
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn event_timing() {
        let start = utils::rdtsc_unsafe();
        println!("start = {:?}", start);
        let mut wheel: TimerWheel<u16> = TimerWheel::new(128, 16 * MILLIS_TO_CYCLES, 128);

        for j in 0..128 {
            let n_millis: u16 = j * 16 + 8;
            let _slot = wheel.schedule(&((n_millis as u64) * MILLIS_TO_CYCLES), n_millis);
            println!("n_millis= {}, slot = {}", n_millis, _slot);
        }

        for _i in 0..1024 {
            // proceed with roughly 2 ms ticks
            thread::sleep(Duration::from_millis(2));
            let now = utils::rdtsc_unsafe();
            match wheel.tick(&now) {
                (Some(mut drain), _more) => {
                    let event = drain.next();
                    if event.is_some() {
                        assert_eq!(&(now - start) / 16 / MILLIS_TO_CYCLES, (event.unwrap() / 16) as u64);
                    } else {
                        assert!(false);
                    }; // there must be one event in each slot
                }
                (None, _more) => (),
            }
        }
        // test that wheel overflow does not break the code:
        wheel.schedule(&((5000 as u64) * MILLIS_TO_CYCLES), 5000);

        let mut found_it: bool = false;
        for _i in 0..1024 {
            // proceed with roughly 2 ms ticks
            thread::sleep(Duration::from_millis(2));
            let now = utils::rdtsc_unsafe();
            match wheel.tick(&now) {
                (Some(mut drain), _more) => {
                    let event = drain.next();
                    if event.is_some() {
                        assert_eq!(5000, event.unwrap() as u64);
                        found_it = true;
                    }
                }
                (None, _more) => (),
            }
        }
        assert!(found_it);
    }
}
