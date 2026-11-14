use crate::{Result, transport::*};
use std::{
    collections::BTreeMap,
    ffi::{CString, c_void},
    os::windows::io::AsRawHandle,
    path::Path,
    process::{Child, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};
use std::{
    fs,
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        JobObjects::*,
        LibraryLoader::{GetProcAddress, LoadLibraryW},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const FIRST: u16 = 16040;
const LAST: u16 = 16439;
type Open = unsafe extern "system" fn(*const u8, u32, i16, u64) -> HANDLE;
type Recv = unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type Shut = unsafe extern "system" fn(HANDLE, u32) -> i32;
type Close = unsafe extern "system" fn(HANDLE) -> i32;
type Compile = unsafe extern "system" fn(*const u8, u32, *mut u8, u32, *mut *const u8, *mut u32) -> i32;
#[repr(C, align(8))]
struct Address {
    bytes: [u8; 80],
}
#[derive(Clone, Copy)]
struct Api {
    open: Open,
    recv: Recv,
    shutdown: Shut,
    close: Close,
    compile: Compile,
}
fn api(root: &Path) -> Result<Api> {
    let path = root.join("WinDivert.dll");
    let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
    if handle.is_null() {
        return Err(format!("Cannot load local WinDivert.dll: {}", unsafe { GetLastError() }).into());
    }
    unsafe fn symbol<T: Copy>(h: HMODULE, name: &[u8]) -> Result<T> {
        let p = unsafe { GetProcAddress(h, name.as_ptr()) }.ok_or("Missing WinDivert API")?;
        Ok(unsafe { std::mem::transmute_copy(&p) })
    }
    // The DLL stays loaded until process exit while function pointers are in use.
    unsafe {
        Ok(Api {
            open: symbol(handle, b"WinDivertOpen\0")?,
            recv: symbol(handle, b"WinDivertRecv\0")?,
            shutdown: symbol(handle, b"WinDivertShutdown\0")?,
            close: symbol(handle, b"WinDivertClose\0")?,
            compile: symbol(handle, b"WinDivertHelperCompileFilter\0")?,
        })
    }
}
fn filter(binding: Binding) -> String {
    format!(
        "ip and tcp and !loopback and !impostor and ifIdx == {} and ((outbound and ip.SrcAddr == {} and tcp.SrcPort >= {FIRST} and tcp.SrcPort <= {LAST} and tcp.DstPort == 443) or (inbound and ip.DstAddr == {} and tcp.DstPort >= {FIRST} and tcp.DstPort <= {LAST} and tcp.SrcPort == 443))",
        binding.index, binding.ip, binding.ip
    )
}
fn compile(api: Api, filter: &str) -> Result<()> {
    let text = CString::new(filter)?;
    let mut error = std::ptr::null();
    let mut pos = 0;
    if unsafe { (api.compile)(text.as_ptr().cast(), 0, std::ptr::null_mut(), 0, &mut error, &mut pos) } == 0 {
        return Err(format!("WinDivert filter rejected at character {pos}").into());
    }
    Ok(())
}
pub(crate) fn elevated() -> Result<bool> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("Cannot query process token".into());
    }
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut length = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut length,
        )
    };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err("Cannot read process elevation".into());
    }
    Ok(elevation.TokenIsElevated != 0)
}
#[derive(Clone, Default)]
struct Counts {
    out: u64,
    incoming: u64,
    synack: u64,
}
struct Observer {
    handle: HANDLE,
    api: Api,
    thread: Option<thread::JoinHandle<std::result::Result<(), String>>>,
    counts: Arc<Mutex<BTreeMap<(Ipv4Addr, u16), Counts>>>,
}
impl Observer {
    fn start(api: Api, text: &str, source: Ipv4Addr) -> Result<Self> {
        let text = CString::new(text)?;
        let handle = unsafe { (api.open)(text.as_ptr().cast(), 0, -30000, 0x1 | 0x4) };
        if handle as isize == -1 {
            return Err(format!("WinDivert passive capture failed: {}", unsafe { GetLastError() }).into());
        }
        let counts = Arc::new(Mutex::new(BTreeMap::<(Ipv4Addr, u16), Counts>::new()));
        let copy = counts.clone();
        let raw = handle as usize;
        let thread = thread::spawn(move || {
            let mut data = vec![0u8; 65575];
            let mut address = Address { bytes: [0; 80] };
            loop {
                let mut length = 0;
                if unsafe {
                    (api.recv)(
                        raw as HANDLE,
                        data.as_mut_ptr().cast(),
                        data.len() as u32,
                        &mut length,
                        &mut address,
                    )
                } == 0
                {
                    let code = unsafe { GetLastError() };
                    if code == 232 || code == 995 {
                        return Ok(());
                    }
                    return Err(format!("Passive capture failed: {code}"));
                }
                let p = &data[..length as usize];
                if p.len() < 40 || p[0] >> 4 != 4 || p[9] != 6 {
                    continue;
                }
                let offset = (p[0] & 15) as usize * 4;
                if p.len() < offset + 20 {
                    continue;
                }
                let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
                let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                let sport = u16::from_be_bytes([p[offset], p[offset + 1]]);
                let dport = u16::from_be_bytes([p[offset + 2], p[offset + 3]]);
                let mut table = copy.lock().map_err(|_| "Capture counter lock poisoned".to_owned())?;
                if src == source {
                    table.entry((dst, sport)).or_default().out += 1;
                } else if dst == source {
                    let c = table.entry((src, dport)).or_default();
                    c.incoming += 1;
                    if p[offset + 13] & 0x12 == 0x12 {
                        c.synack += 1;
                    }
                }
            }
        });
        Ok(Self { handle, api, thread: Some(thread), counts })
    }
    fn stop(mut self) -> Result<()> {
        self.finish()
    }
    fn finish(&mut self) -> Result<()> {
        if self.thread.is_none() {
            return Ok(());
        }
        if unsafe { (self.api.shutdown)(self.handle, 1) } == 0 {
            return Err("Cannot shut down passive capture".into());
        }
        let result = self.thread.take().unwrap().join().map_err(|_| "Capture thread panicked")?;
        unsafe { (self.api.close)(self.handle) };
        result.map_err(Into::into)
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        if let Err(e) = self.finish() {
            eprintln!("Capture cleanup: {e}");
        }
    }
}
struct Worker {
    child: Child,
    job: HANDLE,
}
impl Worker {
    fn start(root: &Path, args: &[String], filter: &str, log: &Path, api: Api) -> Result<Self> {
        unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(0x1 | 0x2 | 0x8000) };
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err("Cannot create owned worker job".into());
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            unsafe { CloseHandle(job) };
            return Err("Cannot set worker exit cleanup".into());
        }
        let output = fs::File::create(log)?;
        let mut child = match Command::new(root.join("winws.exe"))
            .arg(format!("--wf-raw={filter}"))
            .args(args)
            .current_dir(root)
            .creation_flags(HIDDEN)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                unsafe { CloseHandle(job) };
                return Err(e.into());
            }
        };
        if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) } == 0 {
            if let Err(e) = child.kill() {
                eprintln!("Worker kill after job failure: {e}");
            }
            if let Err(e) = child.wait() {
                eprintln!("Worker wait after job failure: {e}");
            }
            unsafe { CloseHandle(job) };
            return Err("Cannot attach worker to cleanup job".into());
        }
        let mut worker = Self { child, job };
        worker.await_capture(api)?;
        Ok(worker)
    }
    fn await_capture(&mut self, api: Api) -> Result<()> {
        let pid = self.child.id();
        let filter = CString::new(format!("processId == {pid}"))?;
        let h = unsafe { (api.open)(filter.as_ptr().cast(), 4, 0, 0x1 | 0x4) };
        if h as isize == -1 {
            return Err(format!("Cannot observe winws readiness: {}", unsafe { GetLastError() }).into());
        }
        let raw = h as usize;
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            let mut data = [0u8; 65575];
            let mut addr = Address { bytes: [0; 80] };
            loop {
                let mut length = 0;
                if unsafe {
                    (api.recv)(raw as HANDLE, data.as_mut_ptr().cast(), data.len() as u32, &mut length, &mut addr)
                } == 0
                {
                    break;
                }
                let owner = u32::from_le_bytes(addr.bytes[24..28].try_into().unwrap());
                let layer = u32::from_le_bytes(addr.bytes[28..32].try_into().unwrap());
                let flags = u64::from_le_bytes(addr.bytes[32..40].try_into().unwrap());
                if addr.bytes[9] == 8 && owner == pid && layer == 0 && flags & 0x8 == 0 {
                    let _ = tx.send(());
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = loop {
            if let Some(status) = self.child.try_wait()? {
                break Err(format!("winws exited before opening capture: {status}").into());
            }
            if rx.recv_timeout(Duration::from_millis(50)).is_ok() {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err("winws did not open its scoped capture handle within 10 seconds".into());
            }
        };
        unsafe { (api.shutdown)(h, 1) };
        let joined = thread.join();
        unsafe { (api.close)(h) };
        if joined.is_err() {
            return Err("WinDivert readiness observer panicked".into());
        }
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.job) };
        if let Err(e) = self.child.wait() {
            eprintln!("Owned winws cleanup failed: {e}");
        }
    }
}

pub(crate) struct Measurement {
    pub response: Option<Response>,
    pub physical: bool,
    pub error: Option<String>,
}

pub(crate) fn measure(
    bin: &Path,
    cache: &Path,
    mut binding: Binding,
    host: &str,
    ip: Ipv4Addr,
    path: &str,
    args: Option<&[String]>,
) -> Result<Measurement> {
    static PORT: AtomicUsize = AtomicUsize::new(0);
    let api = api(bin)?;
    for _ in FIRST..=LAST {
        binding.port = FIRST + (PORT.fetch_add(1, Ordering::Relaxed) % usize::from(LAST - FIRST + 1)) as u16;
        let socket = match reserve(binding) {
            Ok(s) => s,
            Err(e) if port_busy(e.as_ref()) => continue,
            Err(e) => return Err(e),
        };
        let capture = filter(binding);
        compile(api, &capture)?;
        let observer = Observer::start(api, &capture, binding.ip)?;
        let exact = format!(
            "{capture} and ((outbound and tcp.SrcPort == {}) or (inbound and tcp.DstPort == {}))",
            binding.port, binding.port
        );
        let mut worker = match args {
            Some(args) => Some(Worker::start(bin, args, &exact, &cache.join("winws-last.log"), api)?),
            None => None,
        };
        let result = request(socket, binding, host, ip, path);
        if result.as_ref().err().is_some_and(|e| port_busy(e.as_ref())) {
            drop(worker);
            observer.stop()?;
            continue;
        }
        thread::sleep(Duration::from_millis(20));
        let count = observer
            .counts
            .lock()
            .map_err(|_| "physical counter lock poisoned")?
            .get(&(ip, binding.port))
            .cloned()
            .unwrap_or_default();
        if let Some(w) = worker.as_mut() {
            if let Some(status) = w.child.try_wait()? {
                return Err(format!("strategy process exited during probe: {status}").into());
            }
        }
        drop(worker);
        observer.stop()?;
        let physical = count.out > 0;
        return match result {
            Ok(response) => Ok(Measurement {
                response: Some(response),
                physical: physical && count.incoming > 0 && count.synack > 0,
                error: None,
            }),
            Err(e) => Ok(Measurement { response: None, physical, error: Some(e.to_string()) }),
        };
    }
    Err("isolated TCP port pool busy; no strategy was charged".into())
}
