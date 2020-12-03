//! A simple bench tool
//!

#![deny(missing_docs)]

use std::time::{Duration, Instant};

/// A simple bench tool
pub struct Bench {
    cycles: u32,
    executed_time_list: Vec<Duration>,
    check_point: u32,
}

impl Bench {
    /// Total number of cycles
    pub fn cycles(mut self, number: u32) -> Self {
        self.cycles = number;
        // Avoid expansion
        self.executed_time_list = Vec::with_capacity(number as usize + 1);
        self
    }

    /// Predict the total time spent on this task on which point(cycles)
    pub fn estimated_point(mut self, point: u32) -> Self {
        self.check_point = point;
        self
    }

    /// Bench function with a init data
    pub fn bench_function_with_init<T, F>(&mut self, name: &str, init: &T, mut fun: F)
    where
        F: FnMut(&T) + 'static,
    {
        self.clean();
        (0..self.cycles).for_each(|index| {
            let start = Instant::now();
            fun(init);
            let stop = Instant::now();
            self.update_executed(start, stop);
            self.check_point(name, index);
        });
        self.output(name)
    }

    /// Bench function with no init data
    pub fn bench_function<F>(&mut self, name: &str, mut fun: F)
    where
        F: FnMut() + 'static,
    {
        self.clean();
        (0..self.cycles).for_each(|index| {
            let start = Instant::now();
            fun();
            let stop = Instant::now();
            self.update_executed(start, stop);
            self.check_point(name, index);
        });
        self.output(name)
    }

    fn output(&mut self, name: &str) {
        self.executed_time_list.sort();
        let total = self.executed_time_list.iter().sum::<Duration>();
        println!(
            "task name: {}\ncycles: {}\ntotal cost: {:?}\naverage: {:?}\nmedian: {:?}\nmax: {:?}\nmin: {:?}\n",
            name,
            self.cycles,
            total,
            total / self.cycles,
            self.executed_time_list[(self.cycles/2) as usize],
            self.executed_time_list[self.cycles as usize - 1],
            self.executed_time_list[0]
        )
    }

    #[inline]
    fn update_executed(&mut self, start: Instant, stop: Instant) {
        let interval = stop - start;

        self.executed_time_list.push(interval);
    }

    #[inline]
    fn check_point(&mut self, name: &str, index: u32) {
        if self.check_point == index {
            self.executed_time_list.sort();
            let estimated_total = self.executed_time_list[(index / 2) as usize] * self.cycles;

            println!(
                "After counting {} cycles, estimated total time spent on task \"{}\" is {:?}",
                index, name, estimated_total
            )
        }
    }

    #[inline]
    fn clean(&mut self) {
        self.executed_time_list.clear();
    }
}

impl Default for Bench {
    fn default() -> Self {
        Bench {
            cycles: 100_000,
            executed_time_list: Vec::with_capacity(100_000 + 1),
            check_point: 10,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Bench;

    #[test]
    fn test_bench() {
        let mut bench = Bench::default();
        bench.bench_function("test", || {
            let _a = 1 + 1;
        })
    }
}
