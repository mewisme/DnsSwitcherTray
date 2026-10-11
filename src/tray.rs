//! Windows-native notification area UI. Uses Win32, not WebView/Tauri.
//! Network operations always execute on background workers.
#[cfg(windows)]
use crate::app::{Action, App};
#[cfg(windows)]
use crate::profiles::Profile;
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::ptr::{null, null_mut};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CreateMutexW;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, HICON, KillTimer, LoadIconW, MB_ICONERROR, MB_OK,
    MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING, MSG, MessageBoxW, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetTimer,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE,
    WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};

#[cfg(windows)]
const TRAY_MESSAGE: u32 = WM_APP + 100;
#[cfg(windows)]
const WORK_DONE: u32 = WM_APP + 101;
#[cfg(windows)]
const TIMER_ID: usize = 1;
#[cfg(windows)]
const ICON_RETRY_TIMER_ID: usize = 2;
#[cfg(windows)]
const ICON_ID: u32 = 1;
#[cfg(windows)]
const APP_ICON_RESOURCE_ID: usize = 1;
#[cfg(windows)]
static APP: OnceLock<Arc<App>> = OnceLock::new();
#[cfg(windows)]
static APP_ICON: OnceLock<usize> = OnceLock::new();
#[cfg(windows)]
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();
#[cfg(windows)]
static LAST_RESULT: OnceLock<Mutex<Option<Result<String, String>>>> = OnceLock::new();
#[cfg(windows)]
static STARTUP_NOTIFICATION_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn fixed_utf16<const N: usize>(text: &str) -> [u16; N] {
    let mut result = [0; N];
    for (destination, character) in result.iter_mut().take(N - 1).zip(text.encode_utf16()) {
        *destination = character;
    }
    result
}

#[cfg(windows)]
fn load_embedded_icon() -> Result<HICON, String> {
    let module = unsafe { GetModuleHandleW(null()) };
    if module.is_null() {
        return Err(format!(
            "Cannot resolve DNS Switcher module handle (Win32 error {}).",
            unsafe { GetLastError() }
        ));
    }

    let icon = unsafe { LoadIconW(module, APP_ICON_RESOURCE_ID as *const u16) };
    if icon.is_null() {
        return Err(format!(
            "Cannot load embedded DNS Switcher icon resource #{APP_ICON_RESOURCE_ID} (Win32 error {}).",
            unsafe { GetLastError() }
        ));
    }
    Ok(icon)
}

#[cfg(windows)]
fn app_icon() -> HICON {
    APP_ICON
        .get()
        .copied()
        .expect("embedded application icon must be initialized before the window") as HICON
}

#[cfg(windows)]
fn notify_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = ICON_ID;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.uCallbackMessage = TRAY_MESSAGE;
    data.hIcon = app_icon();
    data.szTip = fixed_utf16::<128>("DNS Switcher - Right-click for DNS profiles");
    data
}

#[cfg(windows)]
fn notify(hwnd: HWND, title: &str, message: &str, error: bool) {
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_INFO;
    data.szInfoTitle = fixed_utf16::<64>(title);
    data.szInfo = fixed_utf16::<256>(message);
    data.dwInfoFlags = if error { NIIF_ERROR } else { NIIF_INFO };
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

#[cfg(windows)]
fn notify_started_once(hwnd: HWND) -> bool {
    if STARTUP_NOTIFICATION_SENT.load(Ordering::Acquire) {
        return true;
    }
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_INFO;
    data.szInfoTitle = fixed_utf16::<64>("DNS Switcher");
    data.szInfo = fixed_utf16::<256>(
        "DNS Switcher is running. Right-click its tray icon to choose an adapter or DNS profile.",
    );
    data.dwInfoFlags = NIIF_INFO;
    // Show only after Windows has registered the tray icon. If Explorer isn't
    // ready, the retry timer will try again without showing duplicate balloons.
    if unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) } != 0 {
        STARTUP_NOTIFICATION_SENT.store(true, Ordering::Release);
        return true;
    }
    false
}

#[cfg(windows)]
unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == *TASKBAR_CREATED.get().unwrap_or(&0) && msg != 0 {
        let tray = notify_data(hwnd);
        unsafe {
            if Shell_NotifyIconW(NIM_ADD, &tray) == 0 || !notify_started_once(hwnd) {
                SetTimer(hwnd, ICON_RETRY_TIMER_ID, 3_000, None);
            }
        }
        return 0;
    }
    match msg {
        TRAY_MESSAGE => {
            if (lp as u32 == WM_RBUTTONUP
                || lp as u32 == WM_LBUTTONUP
                || lp as u32 == WM_CONTEXTMENU)
                && let Some(app) = APP.get()
            {
                show_menu(hwnd, app);
            }
            0
        }
        WORK_DONE => {
            if let Some(result) = LAST_RESULT
                .get()
                .and_then(|slot| slot.lock().ok())
                .and_then(|mut slot| slot.take())
            {
                match result {
                    Ok(message) => notify(hwnd, "DNS Switcher", &message, false),
                    Err(message) => notify(hwnd, "DNS Switcher - Attention", &message, true),
                }
            }
            0
        }
        WM_TIMER if wp == TIMER_ID => {
            if let Some(app) = APP.get().cloned() {
                std::thread::spawn(move || {
                    let _ = app.handle(Action::Refresh);
                });
            }
            0
        }
        WM_TIMER if wp == ICON_RETRY_TIMER_ID => {
            let tray = notify_data(hwnd);
            unsafe {
                if (Shell_NotifyIconW(NIM_ADD, &tray) != 0
                    || Shell_NotifyIconW(NIM_MODIFY, &tray) != 0)
                    && notify_started_once(hwnd)
                {
                    KillTimer(hwnd, ICON_RETRY_TIMER_ID);
                }
            }
            0
        }
        WM_CLOSE => {
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            let data = notify_data(hwnd);
            unsafe {
                KillTimer(hwnd, TIMER_ID);
                KillTimer(hwnd, ICON_RETRY_TIMER_ID);
                Shell_NotifyIconW(NIM_DELETE, &data);
                PostQuitMessage(0);
            }
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

#[cfg(windows)]
fn label(
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    id: usize,
    text: &str,
    flags: u32,
) {
    let caption = utf16(text);
    unsafe {
        AppendMenuW(menu, MF_STRING | flags, id, caption.as_ptr());
    }
}

#[cfg(windows)]
fn separator(menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU) {
    unsafe {
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
    }
}

#[cfg(windows)]
fn submenu(
    parent: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    title: &str,
    child: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
) {
    let label = utf16(title);
    unsafe {
        AppendMenuW(parent, MF_POPUP, child as usize, label.as_ptr());
    }
}

#[cfg(windows)]
fn show_menu(hwnd: HWND, app: &Arc<App>) {
    let view = app.snapshot();
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    let mut map: HashMap<u32, Action> = HashMap::new();
    let mut next_id: u32 = 1001;

    label(
        menu,
        0,
        &format!(
            "DNS Switcher  |  {}",
            if view.elevated {
                "Administrator"
            } else {
                "Not elevated"
            }
        ),
        MF_GRAYED,
    );
    label(menu, 0, &truncate(&view.status, 90), MF_GRAYED);
    separator(menu);

    let adapter_menu = unsafe { CreatePopupMenu() };
    for adapter in &view.adapters {
        let id = next_id;
        next_id += 1;
        let mut text = format!("{} — {}", adapter.name, adapter.description);
        if !adapter.connected {
            text.push_str(" [Disconnected]");
        }
        label(
            adapter_menu,
            id as usize,
            &truncate(&text, 95),
            (if adapter.selected { MF_CHECKED } else { 0 })
                | (if adapter.connected && !view.busy {
                    0
                } else {
                    MF_GRAYED
                }),
        );
        map.insert(id, Action::SelectAdapter(adapter.id.clone()));
    }
    if view.adapters.is_empty() {
        label(adapter_menu, 0, "No adapters found - Refresh", MF_GRAYED);
    }
    submenu(
        menu,
        &format!(
            "Adapter: {}",
            view.selected_name.as_deref().unwrap_or("Choose...")
        ),
        adapter_menu,
    );
    separator(menu);

    let mut grouped: Vec<(&str, Vec<&Profile>)> = Vec::new();
    for profile in view.profiles {
        let group = if profile.id.starts_with("adguard") {
            "AdGuard DNS"
        } else if profile.id.starts_with("opendns") {
            "OpenDNS"
        } else if profile.id.starts_with("controld") {
            "Control D"
        } else if profile.id.starts_with("cleanbrowsing") {
            "CleanBrowsing"
        } else {
            "Standard"
        };
        if let Some((_, entries)) = grouped.iter_mut().find(|(name, _)| *name == group) {
            entries.push(profile);
        } else {
            grouped.push((group, vec![profile]));
        }
    }

    for (group, profiles) in &grouped {
        if *group == "Standard" {
            for profile in profiles {
                let id = next_id;
                next_id += 1;
                let checked = view.active_profile == Some(profile.id);
                label(
                    menu,
                    id as usize,
                    profile.name,
                    (if checked { MF_CHECKED } else { 0 })
                        | (if view.selected_name.is_some() && !view.busy {
                            0
                        } else {
                            MF_GRAYED
                        }),
                );
                map.insert(id, Action::ApplyProfile(profile.id));
            }
            separator(menu);
        } else {
            let child = unsafe { CreatePopupMenu() };
            for profile in profiles {
                let id = next_id;
                next_id += 1;
                let checked = view.active_profile == Some(profile.id);
                label(
                    child,
                    id as usize,
                    profile.name,
                    (if checked { MF_CHECKED } else { 0 })
                        | (if view.selected_name.is_some() && !view.busy {
                            0
                        } else {
                            MF_GRAYED
                        }),
                );
                map.insert(id, Action::ApplyProfile(profile.id));
            }
            submenu(menu, group, child);
        }
    }
    separator(menu);
    let refresh_id = next_id;
    next_id += 1;
    label(
        menu,
        refresh_id as usize,
        "Refresh network status",
        if view.busy { MF_GRAYED } else { 0 },
    );
    map.insert(refresh_id, Action::Refresh);
    let startup_id = next_id;
    next_id += 1;
    if view.autostart {
        label(
            menu,
            startup_id as usize,
            "Disable elevated autostart",
            if view.busy { MF_GRAYED } else { 0 },
        );
        map.insert(startup_id, Action::RemoveStartup);
    } else {
        label(
            menu,
            startup_id as usize,
            "Enable elevated autostart (one-time setup)",
            if view.busy { MF_GRAYED } else { 0 },
        );
        map.insert(startup_id, Action::InstallStartup);
    }
    separator(menu);
    let exit_id = next_id;
    // An in-flight DNS transaction must be allowed to finish and verify its
    // rollback before the tray process is allowed to exit.
    label(
        menu,
        exit_id as usize,
        "Exit DNS Switcher",
        if view.busy { MF_GRAYED } else { 0 },
    );
    map.insert(exit_id, Action::Quit);

    let mut cursor = POINT { x: 0, y: 0 };
    unsafe {
        GetCursorPos(&mut cursor);
        SetForegroundWindow(hwnd);
        let clicked = TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_RETURNCMD,
            cursor.x,
            cursor.y,
            0,
            hwnd,
            null(),
        );
        // Destroying the parent menu cleans up all submenu handles.
        DestroyMenu(menu);
        if clicked != 0
            && let Some(action) = map.remove(&(clicked as u32))
        {
            if matches!(action, Action::Quit) {
                DestroyWindow(hwnd);
            } else {
                let app = Arc::clone(app);
                let destination = hwnd as usize;
                std::thread::spawn(move || {
                    let outcome = app.handle(action);
                    if let Some(slot) = LAST_RESULT.get()
                        && let Ok(mut result) = slot.lock()
                    {
                        *result = Some(outcome);
                    }
                    PostMessageW(destination as HWND, WORK_DONE, 0, 0);
                });
            }
        }
    }
}

#[cfg(windows)]
fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_owned()
    } else {
        format!(
            "{}...",
            value.chars().take(max_chars - 3).collect::<String>()
        )
    }
}

#[cfg(windows)]
pub fn run(app: Arc<App>) -> Result<(), String> {
    let icon = load_embedded_icon()?;
    let mutex_name = utf16("Local\\DnsSwitcherRustTray");
    let singleton = unsafe { CreateMutexW(null(), 0, mutex_name.as_ptr()) };
    if singleton.is_null() {
        return Err("Cannot create tray singleton.".to_string());
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            CloseHandle(singleton);
        }
        return Ok(());
    }
    if APP_ICON.set(icon as usize).is_err() {
        unsafe {
            CloseHandle(singleton);
        }
        return Err("Application icon is already initialized.".to_string());
    }
    if APP.set(app).is_err() {
        unsafe {
            CloseHandle(singleton);
        }
        return Err("Tray application is already initialized.".to_string());
    }
    LAST_RESULT.get_or_init(|| Mutex::new(None));
    let taskbar = utf16("TaskbarCreated");
    TASKBAR_CREATED.get_or_init(|| unsafe { RegisterWindowMessageW(taskbar.as_ptr()) });

    let class_name = utf16("DnsSwitcherRustTrayHiddenWindow");
    let title = utf16("DNS Switcher");
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: app_icon(),
        lpszClassName: class_name.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        unsafe {
            CloseHandle(singleton);
        }
        return Err("Cannot register Win32 tray window class.".into());
    }
    let window = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if window.is_null() {
        unsafe {
            CloseHandle(singleton);
        }
        return Err("Cannot create hidden notification window.".to_string());
    }
    let data = notify_data(window);
    if unsafe { Shell_NotifyIconW(NIM_ADD, &data) } == 0 || !notify_started_once(window) {
        // At Windows logon, Task Scheduler may launch this app before
        // Explorer's notification area is ready. Retry icon/notification
        // registration without exiting.
        unsafe {
            SetTimer(window, ICON_RETRY_TIMER_ID, 3_000, None);
        }
    }
    if let Some(app) = APP.get().cloned() {
        std::thread::spawn(move || {
            let _ = app.handle(Action::Refresh);
        });
    }
    unsafe {
        SetTimer(window, TIMER_ID, 30_000, None);
    }
    let mut message: MSG = unsafe { std::mem::zeroed() };
    loop {
        let value = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if value == -1 {
            unsafe {
                DestroyWindow(window);
                CloseHandle(singleton);
            }
            return Err("Win32 tray message loop failed.".to_string());
        }
        if value == 0 {
            break;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    unsafe {
        CloseHandle(singleton);
    }
    Ok(())
}

#[cfg(windows)]
pub fn fatal_message(title: &str, error: &str) {
    let name = utf16(title);
    let body = utf16(error);
    unsafe {
        MessageBoxW(
            null_mut(),
            body.as_ptr(),
            name.as_ptr(),
            MB_ICONERROR | MB_OK,
        );
    }
}

#[cfg(not(windows))]
pub fn run(_app: std::sync::Arc<crate::app::App>) -> Result<(), String> {
    Err("DNS Switcher tray requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn fatal_message(_title: &str, _error: &str) {}
