#![allow(non_snake_case, clippy::let_and_return)]
use std::{
    borrow::Cow,
    cmp::min,
    collections::HashMap,
    ffi::{c_char, c_void, CStr, CString, OsString},
    fs::File,
    io::Read,
    iter::{Cloned, Peekable},
    path::PathBuf,
    process::exit,
    sync::Mutex,
};

use anyhow::{Context, Result};
use encoding_rs::SHIFT_JIS;
use lazy_static::lazy_static;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, SetLastError, BOOL, GENERIC_ACCESS_RIGHTS, GENERIC_READ,
            HANDLE, INVALID_HANDLE_VALUE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileA, GetFileSize, GetFullPathNameA, ReadFile, SetFilePointer, FILE_BEGIN,
            FILE_CREATION_DISPOSITION, FILE_CURRENT, FILE_END, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_SHARE_MODE, SET_FILE_POINTER_MOVE_METHOD,
        },
        System::{Environment::GetCommandLineA, LibraryLoader::SetDllDirectoryA, IO::OVERLAPPED},
    },
};

/// Whether to hook and encode a file.
fn is_text_file(path: &str) -> bool {
    path.ends_with(".c")
        || path.ends_with(".cc")
        || path.ends_with(".cp")
        || path.ends_with(".cpp")
        || path.ends_with(".cxx")
        || path.ends_with(".h")
        || path.ends_with(".hh")
        || path.ends_with(".hp")
        || path.ends_with(".hpp")
        || path.ends_with(".hxx")
}

macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug")]
        {
            // Writing to console will overwrite LastError
            let err = unsafe { GetLastError() };
            eprintln!($($arg)*);
            unsafe { SetLastError(err) };
        }
    };
}

fn main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() < 2 {
        println!("Usage: {} <exe>", args[0].to_string_lossy());
        exit(1);
    }

    let path = PathBuf::from(&args[1]);
    let parent = CString::new(
        path.parent()
            .context("Failed to get executable parent directory")?
            .to_string_lossy()
            .as_ref(),
    )
    .unwrap();
    let parent =
        get_full_path(&parent).expect("Failed to get absolute executable parent directory");
    unsafe { SetDllDirectoryA(PCSTR(parent.as_ptr() as *const u8)) }
        .ok()
        .context("SetDllDirectoryA() failed")?;
    debug_println!("SetDllDirectoryA({:?})", parent.to_string_lossy());

    let mut buf = Vec::new();
    File::open(&path)
        .with_context(|| format!("Failed to open executable: '{}'", path.display()))?
        .read_to_end(&mut buf)
        .with_context(|| format!("Failed to read executable: '{}'", path.display()))?;

    let mut hooks = HashMap::new();
    hooks.insert("kernel32.dll!GetCommandLineA".into(), hook_GetCommandLineA as *const c_void);
    hooks.insert("kernel32.dll!GetCommandLineW".into(), hook_GetCommandLineW as *const c_void);
    hooks.insert("kernel32.dll!CreateFileA".into(), hook_CreateFileA as *const c_void);
    hooks.insert("kernel32.dll!CreateFileW".into(), hook_CreateFileW as *const c_void);
    hooks.insert("kernel32.dll!GetFileSize".into(), hook_GetFileSize as *const c_void);
    hooks.insert("kernel32.dll!CloseHandle".into(), hook_CloseHandle as *const c_void);
    hooks.insert("kernel32.dll!ReadFile".into(), hook_ReadFile as *const c_void);
    hooks.insert("kernel32.dll!SetFilePointer".into(), hook_SetFilePointer as *const c_void);
    unsafe { memexec::memexec_exe_with_hooks(&buf, &hooks) }.expect("Failed to execute");
    Ok(())
}

/// File that has been read into memory and encoded.
struct FileHandle {
    data: Vec<u8>,
    pos: u64,
}

/// Global state shared between hooks.
#[derive(Default)]
struct GlobalState {
    cmdline: Option<CString>,
    file_handles: HashMap<isize, FileHandle>,
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Default::default();
}

/// `GetCommandLineA` hook. Skips our own executable name and replaces the subprocess path with an absolute path.
extern "stdcall" fn hook_GetCommandLineA() -> PCSTR {
    let mut guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
    if let Some(str) = &guard.cmdline {
        return PCSTR(str.as_ptr() as *const u8);
    }

    fn next_arg<'a>(
        iter: &mut Peekable<Cloned<impl Iterator<Item = &'a u8>>>,
        mut cb: impl FnMut(u8),
    ) {
        while iter.peek().cloned() == Some(b' ') {
            iter.next();
        }
        let mut quoted = false;
        if iter.peek().cloned() == Some(b'"') {
            quoted = true;
            iter.next();
        }
        loop {
            let Some(c) = iter.next() else {
                if quoted {
                    panic!("GetCommandLineA(): Unterminated quoted string");
                }
                break;
            };
            if quoted {
                if c == b'"' {
                    let next = iter.next();
                    if next != Some(b' ') && next.is_some() {
                        panic!(
                            "GetCommandLineA(): Expected space after quote, got '{}'",
                            char::from(next.unwrap())
                        );
                    }
                    break;
                }
            } else if c == b' ' {
                break;
            }
            cb(c);
        }
    }

    let cmdline = unsafe { GetCommandLineA() };
    let cmdline = unsafe { cmdline.as_bytes() };
    let mut iter = cmdline.iter().cloned().peekable();
    next_arg(&mut iter, |_| {}); // Skip executable name
    let mut exe = Vec::new();
    next_arg(&mut iter, |c| exe.push(c));
    exe.push(0);
    let absolute_path =
        get_full_path(unsafe { CStr::from_bytes_with_nul_unchecked(exe.as_slice()) })
            .expect("Failed to get absolute path");

    let mut cmdline = vec![b'"'];
    cmdline.extend_from_slice(absolute_path.as_bytes());
    cmdline.push(b'"');
    if iter.peek().is_some() {
        cmdline.push(b' ');
        cmdline.extend(iter);
    }
    cmdline.push(0);
    guard.cmdline = Some(unsafe { CString::from_vec_with_nul_unchecked(cmdline) });
    PCSTR(guard.cmdline.as_ref().unwrap().as_ptr() as *const u8)
}

/// `GetCommandLineW` hook. Currently unsupported.
extern "stdcall" fn hook_GetCommandLineW() -> PCSTR {
    panic!("GetCommandLineW() is not supported");
}

/// `CreateFileA` hook. If it's a text file, read it into memory and encode it as Shift-JIS.
extern "stdcall" fn hook_CreateFileA(
    lpFileName: PCSTR,
    dwDesiredAccess: GENERIC_ACCESS_RIGHTS,
    dwShareMode: FILE_SHARE_MODE,
    lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    dwCreationDisposition: FILE_CREATION_DISPOSITION,
    dwFlagsAndAttributes: FILE_FLAGS_AND_ATTRIBUTES,
    hTemplateFile: HANDLE,
) -> HANDLE {
    let ret = unsafe {
        CreateFileA(
            lpFileName,
            dwDesiredAccess.0,
            dwShareMode,
            Some(lpSecurityAttributes),
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile,
        )
    }
    .unwrap_or(INVALID_HANDLE_VALUE);
    let err = unsafe { GetLastError() };

    let path = unsafe { CStr::from_ptr(lpFileName.as_ptr() as *const c_char) }.to_string_lossy();
    if !ret.is_invalid() && dwDesiredAccess == GENERIC_READ && is_text_file(&path) {
        let mut filesize_high = 0u32;
        let mut filesize = unsafe { GetFileSize(ret, Some(&mut filesize_high)) } as u64;
        filesize |= (filesize_high as u64) << 32;

        if filesize < u32::MAX as u64 {
            let mut data = vec![0u8; filesize as usize];
            let mut bytes_read = 0u32;
            if unsafe {
                ReadFile(
                    ret,
                    Some(data.as_mut_ptr() as *mut c_void),
                    filesize as u32,
                    Some(&mut bytes_read),
                    None,
                )
            }
            .as_bool()
                && bytes_read == filesize as u32
            {
                if let Ok(str) = std::str::from_utf8(&data) {
                    let (encoded, _, _) = SHIFT_JIS.encode(str);
                    let mut guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
                    match encoded {
                        Cow::Borrowed(_) => {
                            // No modifications were made, use the original data
                            guard.file_handles.insert(ret.0, FileHandle { data, pos: 0 });
                        }
                        Cow::Owned(data) => {
                            guard.file_handles.insert(ret.0, FileHandle { data, pos: 0 });
                        }
                    }
                }
            }
        }
    }
    debug_println!("CreateFileA({}, {:#X}) = {:#X}", path, dwDesiredAccess.0, ret.0 as u32);
    unsafe { SetLastError(err) };
    ret
}

/// `CreateFileW` hook. Currently unsupported.
extern "stdcall" fn hook_CreateFileW(
    _lpFileName: PCWSTR,
    _dwDesiredAccess: GENERIC_ACCESS_RIGHTS,
    _dwShareMode: FILE_SHARE_MODE,
    _lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    _dwCreationDisposition: FILE_CREATION_DISPOSITION,
    _dwFlagsAndAttributes: FILE_FLAGS_AND_ATTRIBUTES,
    _hTemplateFile: HANDLE,
) -> HANDLE {
    panic!("CreateFileW() is not supported");
}

/// `GetFileSize` hook. If the file was read into memory, return that size instead.
extern "stdcall" fn hook_GetFileSize(hFile: HANDLE, lpFileSizeHigh: *mut u32) -> u32 {
    if !hFile.is_invalid() {
        let guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
        if let Some(file) = guard.file_handles.get(&hFile.0) {
            debug_println!("OVERRIDE: GetFileSize({:#X}) = {:#X}", hFile.0, file.data.len() as u32);
            return file.data.len() as u32;
        }
    }

    let ret = unsafe { GetFileSize(hFile, Some(lpFileSizeHigh)) };
    debug_println!("GetFileSize({:#X}, {:?}) = {:#X}", hFile.0, lpFileSizeHigh, ret);
    ret
}

/// `CloseHandle` hook. If the file was read into memory, free it.
extern "stdcall" fn hook_CloseHandle(hObject: HANDLE) -> BOOL {
    if !hObject.is_invalid() {
        let mut guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
        if guard.file_handles.remove(&hObject.0).is_some() {
            debug_println!("File handle removed: {:#X}", hObject.0);
        }
    }

    let ret = unsafe { CloseHandle(hObject) };
    debug_println!("CloseHandle({:#X}) = {:#X}", hObject.0, ret.0);
    ret
}

/// `ReadFile` hook. If the file was read into memory, read from that instead.
extern "stdcall" fn hook_ReadFile(
    hFile: HANDLE,
    lpBuffer: *mut c_void,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
) -> BOOL {
    if !hFile.is_invalid() {
        let mut guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
        if let Some(file) = guard.file_handles.get_mut(&hFile.0) {
            let count = min(
                nNumberOfBytesToRead,
                u32::try_from(file.data.len() as u64 - file.pos).unwrap_or(u32::MAX),
            );
            unsafe {
                std::ptr::copy_nonoverlapping(
                    file.data.as_ptr().offset(file.pos as isize),
                    lpBuffer as *mut u8,
                    count as usize,
                );
            }
            file.pos += count as u64;
            if !lpNumberOfBytesRead.is_null() {
                unsafe { *lpNumberOfBytesRead = count };
            }
            debug_println!(
                "OVERRIDE: ReadFile({:#X}, {:?}, {:#X}, {:?}) = {:#X}",
                hFile.0,
                lpBuffer,
                nNumberOfBytesToRead,
                lpNumberOfBytesRead,
                count
            );
            return true.into();
        }
    }

    let ret = unsafe {
        ReadFile(
            hFile,
            Some(lpBuffer),
            nNumberOfBytesToRead,
            Some(lpNumberOfBytesRead),
            Some(lpOverlapped),
        )
    };
    debug_println!(
        "ReadFile({:#X}, {:?}, {:#X}, {:?}) = {:#X}",
        hFile.0,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        ret.0
    );
    ret
}

/// `SetFilePointer` hook. If the file was read into memory, set the position in that instead.
extern "stdcall" fn hook_SetFilePointer(
    hFile: HANDLE,
    lDistanceToMove: i32,
    lpDistanceToMoveHigh: *mut i32,
    dwMoveMethod: SET_FILE_POINTER_MOVE_METHOD,
) -> u32 {
    if !hFile.is_invalid() {
        let mut guard = GLOBAL_STATE.lock().expect("Failed to lock global state");
        if let Some(file) = guard.file_handles.get_mut(&hFile.0) {
            let distance_to_move_high =
                if lpDistanceToMoveHigh.is_null() { 0 } else { unsafe { *lpDistanceToMoveHigh } };
            let distance_to_move = lDistanceToMove as i64 | (distance_to_move_high as i64) << 32;
            let file_size = file.data.len() as u64;
            let pos = min(
                match dwMoveMethod {
                    FILE_BEGIN => distance_to_move as u64,
                    FILE_CURRENT => file.pos.saturating_add_signed(distance_to_move),
                    FILE_END => file_size.saturating_add_signed(distance_to_move),
                    _ => panic!("SetFilePointer(): Unsupported move method {:#X}", dwMoveMethod.0),
                },
                file_size,
            );
            file.pos = pos;
            debug_println!(
                "OVERRIDE SetFilePointer({:#X}, {:#X}, {:?}, {}) = {:#X}",
                hFile.0,
                distance_to_move,
                lpDistanceToMoveHigh,
                dwMoveMethod.0,
                pos
            );
            if !lpDistanceToMoveHigh.is_null() {
                unsafe { *lpDistanceToMoveHigh = (pos >> 32) as i32 };
            }
            return pos as u32;
        }
    }

    let ret =
        unsafe { SetFilePointer(hFile, lDistanceToMove, Some(lpDistanceToMoveHigh), dwMoveMethod) };
    debug_println!(
        "SetFilePointer({:#X}, {:#X}, {:?}, {}) = {:#X}",
        hFile.0,
        lDistanceToMove,
        lpDistanceToMoveHigh,
        dwMoveMethod.0,
        ret
    );
    ret
}

/// Get the absolute path of a file.
fn get_full_path(path: &CStr) -> Result<CString> {
    let mut buf = [0u8; 4096];
    let len =
        unsafe { GetFullPathNameA(PCSTR(path.as_ptr() as *const u8), Some(buf.as_mut()), None) };
    if len == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { CString::from_vec_with_nul_unchecked(buf[..len as usize + 1].to_vec()) })
}
