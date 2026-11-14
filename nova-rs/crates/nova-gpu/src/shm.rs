//! Named shared-memory frame slot for `gpu-serve`, and process CPU time.
//!
//! Layout: 32-byte header `[u64 seq][u32 w][u32 h][u32 stride][u32 reserved x3]`, then RGB8 top-down.
//! The writer stores pixels and w/h/stride first and bumps `seq` last with release ordering.

/// Header size in bytes.
pub const HEADER: usize = 32;

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateWaitableTimerExW, GetCurrentProcess, GetProcessTimes, INFINITE,
        SetWaitableTimer, TIMER_ALL_ACCESS, WaitForSingleObject,
    };

    use super::HEADER;

    pub struct FrameMap {
        handle: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
        size: usize,
        name: String,
    }

    impl FrameMap {
        /// Create a named mapping of `capacity` pixel bytes plus the header.
        pub fn create(name: &str, capacity: usize) -> Result<FrameMap, String> {
            let size = capacity + HEADER;
            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    (size as u64 >> 32) as u32,
                    size as u32,
                    &HSTRING::from(name),
                )
                .map_err(|e| format!("CreateFileMappingW({name}): {e}"))?;
                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size);
                if view.Value.is_null() {
                    let _ = CloseHandle(handle);
                    return Err(format!("MapViewOfFile({name}) failed"));
                }
                std::ptr::write_bytes(view.Value.cast::<u8>(), 0, HEADER);
                Ok(FrameMap { handle, view, size, name: name.to_owned() })
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        /// Total mapping size, header included.
        pub fn size(&self) -> usize {
            self.size
        }

        /// The pixel area (everything after the header).
        pub fn pixels(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.view.Value.cast::<u8>().add(HEADER), self.size - HEADER) }
        }

        /// Publish a frame whose pixels are already in `pixels()`: geometry first, `seq` last (release).
        pub fn publish(&mut self, seq: u64, w: u32, h: u32) {
            unsafe {
                let base = self.view.Value.cast::<u8>();
                let words = base.add(8).cast::<u32>();
                words.write_volatile(w);
                words.add(1).write_volatile(h);
                words.add(2).write_volatile(w * 3);
                (*base.cast::<AtomicU64>()).store(seq, Ordering::Release);
            }
        }
    }

    impl Drop for FrameMap {
        fn drop(&mut self) {
            unsafe {
                let _ = UnmapViewOfFile(self.view);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    /// Frame pacing on an absolute deadline with a high-resolution waitable timer
    /// (CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, Windows 10 1803+); falls back to std's sleep.
    pub struct Pacer {
        timer: Option<HANDLE>,
    }

    impl Pacer {
        pub fn new() -> Pacer {
            let timer = unsafe {
                CreateWaitableTimerExW(None, None, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS.0).ok()
            };
            Pacer { timer }
        }

        pub fn high_resolution(&self) -> bool {
            self.timer.is_some()
        }

        pub fn sleep_until(&self, deadline: std::time::Instant) {
            let now = std::time::Instant::now();
            if deadline <= now {
                return;
            }
            let d = deadline - now;
            if let Some(t) = self.timer {
                // negative = relative, in 100 ns units
                let due = -((d.as_nanos() / 100).max(1) as i64);
                unsafe {
                    if SetWaitableTimer(t, &due, 0, None, None, false).is_ok() {
                        WaitForSingleObject(t, INFINITE);
                        return;
                    }
                }
            }
            std::thread::sleep(d);
        }
    }

    impl Default for Pacer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for Pacer {
        fn drop(&mut self) {
            if let Some(t) = self.timer.take() {
                unsafe {
                    let _ = CloseHandle(t);
                }
            }
        }
    }

    /// User + kernel CPU seconds consumed by this process so far.
    pub fn process_cpu_seconds() -> f64 {
        let ft = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32 | u64::from(f.dwLowDateTime)) as f64 * 1e-7;
        let (mut c, mut e, mut k, mut u) =
            (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        unsafe {
            if GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u).is_err() {
                return 0.0;
            }
        }
        ft(k) + ft(u)
    }
}

#[cfg(not(windows))]
mod imp {
    pub struct FrameMap;

    impl FrameMap {
        pub fn create(_name: &str, _capacity: usize) -> Result<FrameMap, String> {
            Err("nova-gpu: shared frame mapping is only implemented on Windows".into())
        }
        pub fn name(&self) -> &str {
            ""
        }
        pub fn size(&self) -> usize {
            0
        }
        pub fn pixels(&mut self) -> &mut [u8] {
            &mut []
        }
        pub fn publish(&mut self, _seq: u64, _w: u32, _h: u32) {}
    }

    #[derive(Default)]
    pub struct Pacer;

    impl Pacer {
        pub fn new() -> Pacer {
            Pacer
        }
        pub fn high_resolution(&self) -> bool {
            false
        }
        pub fn sleep_until(&self, deadline: std::time::Instant) {
            let now = std::time::Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
        }
    }

    pub fn process_cpu_seconds() -> f64 {
        0.0
    }
}

pub use imp::{process_cpu_seconds, FrameMap, Pacer};
