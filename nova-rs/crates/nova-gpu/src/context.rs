//! Headless OpenGL 3.3-core context: hidden window + WGL (legacy context -> wglCreateContextAttribsARB).
//! Software GL (Microsoft "GDI Generic", GL 1.1) is rejected so the caller falls back to the CPU renderer.

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, CString};

    use glow::HasContext;
    use windows::core::{w, PCSTR};
    use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Gdi::{GetDC, ReleaseDC, HDC};
    use windows::Win32::Graphics::OpenGL::{
        wglCreateContext, wglDeleteContext, wglGetProcAddress, wglMakeCurrent, ChoosePixelFormat, SetPixelFormat,
        HGLRC, PFD_DOUBLEBUFFER, PFD_DRAW_TO_WINDOW, PFD_MAIN_PLANE, PFD_SUPPORT_OPENGL, PFD_TYPE_RGBA,
        PIXELFORMATDESCRIPTOR,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, WINDOW_EX_STYLE, WNDCLASSW,
        WS_OVERLAPPEDWINDOW,
    };

    const WGL_CONTEXT_MAJOR_VERSION_ARB: i32 = 0x2091;
    const WGL_CONTEXT_MINOR_VERSION_ARB: i32 = 0x2092;
    const WGL_CONTEXT_PROFILE_MASK_ARB: i32 = 0x9126;
    const WGL_CONTEXT_CORE_PROFILE_BIT_ARB: i32 = 0x0001;

    type CreateContextAttribs = unsafe extern "system" fn(HDC, HGLRC, *const i32) -> HGLRC;

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
    }

    /// A current GL 3.3-core context bound to the creating thread (not Send).
    pub struct GlContext {
        gl: Option<glow::Context>,
        hwnd: HWND,
        hdc: HDC,
        hglrc: HGLRC,
        renderer: String,
        version: String,
    }

    impl GlContext {
        pub fn new() -> Result<GlContext, String> {
            unsafe { Self::create() }
        }

        unsafe fn create() -> Result<GlContext, String> {
            unsafe {
                let hinstance = GetModuleHandleW(None).map_err(|e| format!("GetModuleHandleW: {e}"))?;
                let class = w!("NovaGpuHiddenWindow");
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: hinstance.into(),
                    lpszClassName: class,
                    ..Default::default()
                };
                // A second context in the same process finds the class already registered: fine.
                let _ = RegisterClassW(&wc);
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    class,
                    w!("nova-gpu"),
                    WS_OVERLAPPEDWINDOW,
                    0,
                    0,
                    64,
                    64,
                    None,
                    None,
                    Some(hinstance.into()),
                    None,
                )
                .map_err(|e| format!("CreateWindowExW: {e}"))?;
                let hdc = GetDC(Some(hwnd));
                if hdc.is_invalid() {
                    let _ = DestroyWindow(hwnd);
                    return Err("GetDC failed".into());
                }
                let mut ctx = GlContext {
                    gl: None,
                    hwnd,
                    hdc,
                    hglrc: HGLRC::default(),
                    renderer: String::new(),
                    version: String::new(),
                };
                // From here on Drop releases whatever was created.
                let pfd = PIXELFORMATDESCRIPTOR {
                    nSize: size_of::<PIXELFORMATDESCRIPTOR>() as u16,
                    nVersion: 1,
                    dwFlags: PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER,
                    iPixelType: PFD_TYPE_RGBA,
                    cColorBits: 32,
                    cAlphaBits: 8,
                    iLayerType: PFD_MAIN_PLANE.0 as u8,
                    ..Default::default()
                };
                let fmt = ChoosePixelFormat(hdc, &pfd);
                if fmt == 0 {
                    return Err("ChoosePixelFormat found no OpenGL pixel format".into());
                }
                SetPixelFormat(hdc, fmt, &pfd).map_err(|e| format!("SetPixelFormat: {e}"))?;
                let legacy = wglCreateContext(hdc).map_err(|e| format!("wglCreateContext: {e}"))?;
                if let Err(e) = wglMakeCurrent(hdc, legacy) {
                    let _ = wglDeleteContext(legacy);
                    return Err(format!("wglMakeCurrent(legacy): {e}"));
                }
                let create_attribs = wglGetProcAddress(PCSTR(c"wglCreateContextAttribsARB".as_ptr().cast()));
                let Some(create_attribs) = create_attribs else {
                    let _ = wglMakeCurrent(HDC::default(), HGLRC::default());
                    let _ = wglDeleteContext(legacy);
                    return Err("no wglCreateContextAttribsARB: software OpenGL only (GDI Generic)".into());
                };
                let create_attribs: CreateContextAttribs = std::mem::transmute(create_attribs);
                let attribs = [
                    WGL_CONTEXT_MAJOR_VERSION_ARB,
                    3,
                    WGL_CONTEXT_MINOR_VERSION_ARB,
                    3,
                    WGL_CONTEXT_PROFILE_MASK_ARB,
                    WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
                    0,
                ];
                let core = create_attribs(hdc, HGLRC::default(), attribs.as_ptr());
                let _ = wglMakeCurrent(HDC::default(), HGLRC::default());
                let _ = wglDeleteContext(legacy);
                if core.is_invalid() {
                    return Err("wglCreateContextAttribsARB(3.3 core) failed".into());
                }
                ctx.hglrc = core;
                wglMakeCurrent(hdc, core).map_err(|e| format!("wglMakeCurrent(core): {e}"))?;

                let opengl32: HMODULE =
                    LoadLibraryW(w!("opengl32.dll")).map_err(|e| format!("opengl32.dll: {e}"))?;
                let gl = glow::Context::from_loader_function(|name| load(opengl32, name));
                ctx.renderer = gl.get_parameter_string(glow::RENDERER);
                ctx.version = gl.get_parameter_string(glow::VERSION);
                ctx.gl = Some(gl);
                let (major, minor) = parse_version(&ctx.version);
                if ctx.renderer.contains("GDI Generic") || (major, minor) < (3, 3) {
                    return Err(format!(
                        "OpenGL 3.3 is not available (renderer {:?}, version {:?})",
                        ctx.renderer, ctx.version
                    ));
                }
                Ok(ctx)
            }
        }

        pub fn gl(&self) -> &glow::Context {
            self.gl.as_ref().expect("GlContext is only handed out fully loaded")
        }

        /// GL_RENDERER string.
        pub fn renderer(&self) -> &str {
            &self.renderer
        }

        /// GL_VERSION string.
        pub fn version(&self) -> &str {
            &self.version
        }
    }

    unsafe fn load(opengl32: HMODULE, name: &str) -> *const c_void {
        let Ok(cname) = CString::new(name) else { return std::ptr::null() };
        unsafe {
            let p = wglGetProcAddress(PCSTR(cname.as_ptr().cast()));
            if let Some(f) = p {
                let v = f as usize;
                // wglGetProcAddress returns 1/2/3/-1 for failures on some drivers
                if !(v <= 3 || v == usize::MAX) {
                    return f as *const c_void;
                }
            }
            match GetProcAddress(opengl32, PCSTR(cname.as_ptr().cast())) {
                Some(f) => f as *const c_void,
                None => std::ptr::null(),
            }
        }
    }

    impl Drop for GlContext {
        fn drop(&mut self) {
            unsafe {
                let _ = wglMakeCurrent(HDC::default(), HGLRC::default());
                if !self.hglrc.is_invalid() {
                    let _ = wglDeleteContext(self.hglrc);
                }
                ReleaseDC(Some(self.hwnd), self.hdc);
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }

    fn parse_version(v: &str) -> (u32, u32) {
        let mut it = v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
        let major = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        (major, minor)
    }
}

#[cfg(not(windows))]
mod imp {
    /// Stub: the native GPU path is Windows-only.
    pub struct GlContext {
        gl: glow::Context,
    }

    impl GlContext {
        pub fn new() -> Result<GlContext, String> {
            Err("nova-gpu: OpenGL context creation is only implemented on Windows".into())
        }
        pub fn gl(&self) -> &glow::Context {
            &self.gl
        }
        pub fn renderer(&self) -> &str {
            ""
        }
        pub fn version(&self) -> &str {
            ""
        }
    }
}

pub use imp::GlContext;
