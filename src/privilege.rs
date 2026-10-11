//! Windows privileges: one consent at installation/startup, never per DNS click.
//! Optional scheduled-task installation uses Program Files ACLs and an
//! interactive-token task registered with admin consent. Nothing bypasses UAC.
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::{ffi::OsStr, process::Command, ptr};
#[cfg(windows)]
use windows_sys::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
#[cfg(windows)]
use windows_sys::Win32::System::Com::CoTaskMemFree;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, IsUserAnAdmin, SHGetKnownFolderPath, ShellExecuteW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

#[cfg(windows)]
const TASK_NAME: &str = "DnsSwitcherRustTray";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(windows)]
pub fn elevated() -> bool {
    // This verifies the current process token rather than group membership
    // from an unelevated UAC-filtered token.
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
pub fn elevated() -> bool {
    false
}

#[cfg(windows)]
pub fn bootstrap() -> Result<bool, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--install-autostart" => {
            if !elevated() {
                launch_elevated(Some(flag))?;
                return Ok(false);
            }
            install_task()?;
            return Ok(false);
        }
        [flag] if flag == "--remove-autostart" => {
            if !elevated() {
                launch_elevated(Some(flag))?;
                return Ok(false);
            }
            remove_task()?;
            return Ok(false);
        }
        [flag] if flag == "--probe" => {
            // Read-only development check: no elevation, no DNS writes.
            println!(
                "DNS Switcher admin: {}; task available: {}",
                elevated(),
                task_exists()
            );
            return Ok(false);
        }
        [] => {}
        _ => {
            return Err(
                "Unsupported arguments. Use --install-autostart, --remove-autostart, or --probe."
                    .to_string(),
            );
        }
    }

    if elevated() {
        return Ok(true);
    }

    // A registered task can start an already-authorized, protected executable
    // in the interactive logon session without prompting for UAC again.
    if task_exists() && start_task().is_ok() {
        return Ok(false);
    }

    // No elevated task registered; first-run UAC approval is unavoidable.
    launch_elevated(None)?;
    Ok(false)
}

#[cfg(not(windows))]
pub fn bootstrap() -> Result<bool, String> {
    Err("The DNS tray application requires Windows.".to_string())
}

#[cfg(windows)]
pub fn task_exists() -> bool {
    let Ok(target) = installed_path() else {
        return false;
    };
    let Ok(xml) = read_task_xml() else {
        return false;
    };
    task_matches_installation(&xml, &target)
}

#[cfg(windows)]
fn read_task_xml() -> Result<String, String> {
    let Ok(schtasks) = crate::dns::trusted_executable("schtasks.exe") else {
        return Err("Windows Task Scheduler utility unavailable.".into());
    };
    let output = Command::new(schtasks)
        .args(["/Query", "/TN", TASK_NAME, "/XML"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("Could not inspect Windows startup task: {error}"))?;
    if !output.status.success() {
        return Err("DNS Switcher startup task has not been installed.".into());
    }
    decode_task_xml(&output.stdout)
}

/// schtasks.exe can return UTF-16 XML on some Windows versions.
#[cfg(windows)]
fn decode_task_xml(output: &[u8]) -> Result<String, String> {
    if output.starts_with(&[0xff, 0xfe]) || output.starts_with(&[0xfe, 0xff]) {
        let little = output.starts_with(&[0xff, 0xfe]);
        if !(output.len() - 2).is_multiple_of(2) {
            return Err("Malformed Windows startup task XML.".into());
        }
        let units = output[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| {
                if little {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    u16::from_be_bytes([bytes[0], bytes[1]])
                }
            })
            .collect::<Vec<_>>();
        return String::from_utf16(&units).map_err(|error| error.to_string());
    }
    String::from_utf8(output.to_vec()).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn unescape_xml(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Never run a task just because its name matches: a task created by an older
/// executable (or another process) must not silently replace this application.
#[cfg(windows)]
fn task_matches_installation(xml: &str, target: &std::path::Path) -> bool {
    if xml.matches("<Exec>").count() != 1 || xml.contains("<ComHandler>") {
        return false;
    }
    let Some(exec_xml) = xml
        .split("<Exec>")
        .nth(1)
        .and_then(|part| part.split("</Exec>").next())
    else {
        return false;
    };
    let Some(command) = exec_xml
        .split("<Command>")
        .nth(1)
        .and_then(|part| part.split("</Command>").next())
    else {
        return false;
    };
    let expected = target.to_string_lossy();
    let command = unescape_xml(command.trim().trim_matches('"'));
    if !command.eq_ignore_ascii_case(&expected) {
        return false;
    }
    // Unexpected task arguments could alter execution; reject them.
    if exec_xml.contains("<Arguments>") && !exec_xml.contains("<Arguments></Arguments>") {
        return false;
    }
    xml.contains("<RunLevel>HighestAvailable</RunLevel>")
        && xml.contains("<LogonType>InteractiveToken</LogonType>")
}
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn rejects_legacy_or_untrusted_autostart_tasks() {
        let expected =
            std::path::Path::new("C:\\Program Files\\DnsSwitcherRustTray\\DnsSwitcherTray.exe");
        let xml = scheduled_task_xml("PC\\User", expected);
        assert!(task_matches_installation(&xml, expected));
        assert!(!task_matches_installation(
            &xml,
            std::path::Path::new("C:\\Program Files\\DnsSwitcherTray\\dnss.exe")
        ));
        assert!(!task_matches_installation(
            &xml.replace("HighestAvailable", "LeastPrivilege"),
            expected
        ));
        assert!(!task_matches_installation(
            &xml.replace("InteractiveToken", "Password"),
            expected
        ));
        assert!(!task_matches_installation(
            &xml.replace("</Exec>", "<Arguments>--other</Arguments></Exec>"),
            expected
        ));
    }

    #[test]
    fn escapes_xml_paths_and_users() {
        let path = std::path::Path::new("C:\\Program Files\\DNS & Tools\\dnss.exe");
        let xml = scheduled_task_xml("PC\\Admin & User", path);
        assert!(xml.contains("Admin &amp; User"));
        assert!(task_matches_installation(&xml, path));
    }

    #[test]
    fn decodes_utf16_task_xml() {
        let xml = scheduled_task_xml(
            "PC\\User",
            std::path::Path::new("C:\\Program Files\\dnss.exe"),
        );
        let bytes = [
            vec![0xff, 0xfe],
            xml.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ]
        .concat();
        assert_eq!(decode_task_xml(&bytes).unwrap(), xml);
        assert!(decode_task_xml(&[0xff, 0xfe, 0x12]).is_err());
    }
}

#[cfg(not(windows))]
pub fn task_exists() -> bool {
    false
}

/// Called from the already-elevated tray menu. Task registration is always
/// an explicit action and never executes during tests or profile switches.
#[cfg(windows)]
pub fn configure_autostart(enabled: bool) -> Result<String, String> {
    if !elevated() {
        return Err("Administrator approval is required before configuring startup.".into());
    }
    if enabled {
        install_task()?;
    } else {
        remove_task()?;
    }
    Ok(if enabled {
        "Elevated autostart installed. Next logon starts DNS Switcher without a new UAC prompt."
    } else {
        "Elevated autostart disabled. Installed files may be removed after exit."
    }
    .to_string())
}

#[cfg(not(windows))]
pub fn configure_autostart(_enabled: bool) -> Result<String, String> {
    Err("Windows only.".into())
}

#[cfg(windows)]
fn start_task() -> Result<(), String> {
    let binary =
        crate::dns::trusted_executable("schtasks.exe").map_err(|error| error.to_string())?;
    let output = Command::new(binary)
        .args(["/Run", "/TN", TASK_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to launch authorized startup task: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Scheduled task launch failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn wide(source: &OsStr) -> Vec<u16> {
    source.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn launch_elevated(argument: Option<&str>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let verb = wide(OsStr::new("runas"));
    let path = wide(exe.as_os_str());
    let options = wide(OsStr::new(argument.unwrap_or("")));
    let code = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            path.as_ptr(),
            options.as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if code <= 32 {
        return Err(format!(
            "Windows Administrator approval was declined or unavailable (ShellExecute: {code})."
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn system_command(executable: &str, args: &[&str]) -> Result<(), String> {
    let binary = crate::dns::trusted_executable(executable).map_err(|e| e.to_string())?;
    let output = Command::new(binary)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{executable}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{executable} failed ({}): {} {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

#[cfg(windows)]
fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn scheduled_task_xml(user: &str, executable: &std::path::Path) -> String {
    let user = xml_text(user);
    let executable = xml_text(&executable.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>DNS Switcher native tray (authorized elevated autostart)</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{executable}</Command></Exec></Actions>
</Task>"#
    )
}

#[cfg(windows)]
fn installed_path() -> Result<std::path::PathBuf, String> {
    // An elevated process must never trust user-controllable environment
    // variables to select the target of an autostart task.
    let mut pointer = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut pointer) };
    if result < 0 || pointer.is_null() {
        return Err(format!(
            "Cannot resolve trusted Program Files folder (HRESULT {result:#x})."
        ));
    }
    let mut length = 0usize;
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    let folder = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) });
    unsafe { CoTaskMemFree(pointer.cast()) };
    let root = std::path::PathBuf::from(folder);
    if !root.is_absolute() {
        return Err("Invalid system Program Files path".into());
    }
    Ok(root.join("DnsSwitcherRustTray").join("DnsSwitcherTray.exe"))
}

#[cfg(windows)]
fn interactive_user() -> Result<String, String> {
    let mut size = 512u32;
    let mut buffer = vec![0u16; size as usize];
    let result = unsafe { GetUserNameExW(NameSamCompatible, buffer.as_mut_ptr(), &mut size) };
    if result == 0 || size == 0 {
        return Err("Could not identify the interactive Windows user.".into());
    }
    Ok(String::from_utf16_lossy(&buffer[..size as usize]))
}

#[cfg(windows)]
fn require_real_path(path: &std::path::Path) -> Result<(), String> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if path.exists() {
        let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "Refusing a reparse-point elevated task target: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn install_task() -> Result<(), String> {
    if !elevated() {
        return Err("Administrator consent is required".into());
    }
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let target = installed_path()?;
    let directory = target.parent().ok_or("Invalid installation directory")?;
    require_real_path(directory)?;
    require_real_path(&target)?;
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    require_real_path(directory)?;
    let dir = directory.to_str().ok_or("Non-Unicode installation path")?;
    // Strip inherited write access. Only SYSTEM and Administrators may modify
    // the installation; ordinary users may execute but cannot replace the task target.
    system_command("icacls.exe", &[dir, "/reset"])?;
    system_command(
        "icacls.exe",
        &[
            dir,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
    )?;
    if source != target {
        std::fs::copy(&source, &target).map_err(|e| format!("Install executable: {e}"))?;
    }
    let exe = target.to_str().ok_or("Non-Unicode executable path")?;
    system_command("icacls.exe", &[exe, "/reset"])?;
    system_command(
        "icacls.exe",
        &[
            exe,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            "*S-1-5-32-545:RX",
        ],
    )?;
    let account = interactive_user()?;
    // Register an InteractiveToken principal from an XML task definition.
    // Unlike schtasks /RU, this never prompts for or stores an account password.
    let xml_path = directory.join("autostart-task.xml");
    require_real_path(&xml_path)?;
    let definition = scheduled_task_xml(&account, &target);
    // Windows Task Scheduler accepts UTF-16 XML and understands paths with
    // non-ASCII characters. Write the temporary XML only to our ACL-locked dir.
    let xml_units = definition.encode_utf16().collect::<Vec<_>>();
    let mut xml_bytes = vec![0xff, 0xfe];
    for unit in xml_units {
        xml_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&xml_path, xml_bytes)
        .map_err(|error| format!("Cannot stage Windows task definition: {error}"))?;
    let xml_arg = xml_path
        .to_str()
        .ok_or("Non-Unicode task definition path")?;
    let creation = system_command(
        "schtasks.exe",
        &["/Create", "/F", "/TN", TASK_NAME, "/XML", xml_arg],
    );
    let _ = std::fs::remove_file(&xml_path);
    creation?;
    if !task_exists() {
        return Err("Windows accepted the startup task, but its protected executable or elevated settings could not be verified.".into());
    }
    Ok(())
}

#[cfg(windows)]
fn remove_task() -> Result<(), String> {
    if !elevated() {
        return Err("Administrator consent is required".into());
    }
    if task_exists() {
        system_command("schtasks.exe", &["/Delete", "/F", "/TN", TASK_NAME])?;
    }
    Ok(())
}
