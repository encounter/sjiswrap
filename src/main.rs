#![allow(non_snake_case, clippy::let_and_return)]
use std::{
    borrow::Cow,
    cmp::min,
    collections::{hash_map::Entry, HashMap},
    ffi::{c_char, c_void, CStr, CString, OsStr, OsString},
    fs::File,
    io::Read,
    iter::{Cloned, Peekable},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    pin::Pin,
    process::exit,
};

use anyhow::{Context, Result};
use encoding_rs::{SHIFT_JIS, UTF_8};
use num::Zero;
use rustc_hash::FxHashMap;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, SetLastError, BOOL, ERROR_INSUFFICIENT_BUFFER,
            ERROR_NO_UNICODE_TRANSLATION, ERROR_SUCCESS, GENERIC_ACCESS_RIGHTS, GENERIC_READ,
            HANDLE, HMODULE, INVALID_HANDLE_VALUE,
        },
        Globalization::{MultiByteToWideChar, MULTI_BYTE_TO_WIDE_CHAR_FLAGS},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileA, GetFileSize, GetFullPathNameA, ReadFile, ReadFileEx, SetFilePointer,
            FILE_BEGIN, FILE_CREATION_DISPOSITION, FILE_CURRENT, FILE_END,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, SET_FILE_POINTER_MOVE_METHOD,
        },
        System::{
            Environment::GetCommandLineA,
            LibraryLoader::SetDllDirectoryA,
            Memory::{
                CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP, FILE_MAP_ALL_ACCESS,
                FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_PROTECTION_FLAGS,
            },
            IO::{LPOVERLAPPED_COMPLETION_ROUTINE, OVERLAPPED},
        },
    },
};

/// Whether to hook and encode a file.
fn is_text_file(path: &Path) -> bool {
    let Some(ext) = path.extension() else {
        return false;
    };
    ext == OsStr::new("c")
        || ext == OsStr::new("cc")
        || ext == OsStr::new("cp")
        || ext == OsStr::new("cpp")
        || ext == OsStr::new("cxx")
        || ext == OsStr::new("h")
        || ext == OsStr::new("hh")
        || ext == OsStr::new("hp")
        || ext == OsStr::new("hpp")
        || ext == OsStr::new("hxx")
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

macro_rules! fail {
    ($($arg:tt)*) => {
        {
            eprintln!($($arg)*);
            exit(1);
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
    let abs_path_cstr =
        get_full_path(&CString::new(path.as_os_str().to_string_lossy().as_ref()).unwrap())
            .context("Failed to get absolute executable path")?;
    let abs_path = PathBuf::from(abs_path_cstr.to_string_lossy().as_ref());
    let parent = abs_path.parent().context("Failed to get absolute executable parent directory")?;
    let parent_cstr = CString::new(parent.as_os_str().to_string_lossy().as_ref()).unwrap();
    unsafe { SetDllDirectoryA(PCSTR(parent_cstr.as_ptr() as *const u8)) }
        .ok()
        .context("SetDllDirectoryA() failed")?;
    debug_println!("SetDllDirectoryA({:?})", parent.to_string_lossy());

    unsafe {
        GLOBAL_STATE = MaybeUninit::new(GlobalState {
            exe_path: abs_path_cstr,
            ..Default::default()
        })
    };

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
    hooks.insert("kernel32.dll!ReadFileEx".into(), hook_ReadFileEx as *const c_void);
    hooks.insert("kernel32.dll!SetFilePointer".into(), hook_SetFilePointer as *const c_void);
    hooks.insert("kernel32.dll!IsDBCSLeadByte".into(), hook_IsDBCSLeadByte as *const c_void);
    hooks
        .insert("kernel32.dll!GetModuleFileNameA".into(), hook_GetModuleFileNameA as *const c_void);
    hooks
        .insert("kernel32.dll!CreateFileMappingA".into(), hook_CreateFileMappingA as *const c_void);
    hooks
        .insert("kernel32.dll!CreateFileMappingW".into(), hook_CreateFileMappingW as *const c_void);
    hooks.insert("kernel32.dll!OpenFileMappingA".into(), hook_OpenFileMappingA as *const c_void);
    hooks.insert("kernel32.dll!OpenFileMappingW".into(), hook_OpenFileMappingW as *const c_void);
    hooks.insert("kernel32.dll!MapViewOfFile".into(), hook_MapViewOfFile as *const c_void);
    hooks.insert("kernel32.dll!MapViewOfFileEx".into(), hook_MapViewOfFileEx as *const c_void);
    hooks.insert("kernel32.dll!UnmapViewOfFile".into(), hook_UnmapViewOfFile as *const c_void);
    hooks.insert(
        "kernel32.dll!MultiByteToWideChar".into(),
        hook_MultiByteToWideChar as *const c_void,
    );
    hooks.insert("kernel32.dll!GetACP".into(), hook_GetACP as *const c_void);
    unsafe { memexec::memexec_exe_with_hooks(&buf, &hooks) }.expect("Failed to execute");
    Ok(())
}

/// File that has been read into memory and encoded.
struct FileHandle {
    path: PathBuf,
    pos: u64,
}

/// Global state shared between hooks.
#[derive(Default)]
struct GlobalState {
    exe_path: CString,
    cmdline: Option<CString>,
    encoded_files: FxHashMap<PathBuf, Pin<Box<[u8]>>>,
    file_handles: FxHashMap<*mut c_void, FileHandle>,
    file_mapping_handles: FxHashMap<*mut c_void, HANDLE>,
    view_to_mapping: FxHashMap<*mut c_void, HANDLE>,
}

impl GlobalState {
    fn file_by_handle(&mut self, handle: HANDLE) -> Option<(&mut FileHandle, Pin<&[u8]>)> {
        self.file_handles
            .get_mut(&handle.0)
            .and_then(|file| self.encoded_files.get(&file.path).map(|data| (file, data.as_ref())))
    }

    fn file_by_mapping_handle(&mut self, handle: HANDLE) -> Option<(&mut FileHandle, Pin<&[u8]>)> {
        self.file_mapping_handles.get(&handle.0).cloned().and_then(|file| self.file_by_handle(file))
    }
}

static mut GLOBAL_STATE: MaybeUninit<GlobalState> = MaybeUninit::uninit();

/// `GetCommandLineA` hook. Skips our own executable name and replaces the subprocess path with an absolute path.
extern "stdcall" fn hook_GetCommandLineA() -> PCSTR {
    let state = unsafe { GLOBAL_STATE.assume_init_mut() };
    if let Some(str) = &state.cmdline {
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
                    fail!("sjiswrap: GetCommandLineA(): Unterminated quoted string");
                }
                break;
            };
            if quoted {
                if c == b'"' {
                    let next = iter.next();
                    if next != Some(b' ') && next.is_some() {
                        fail!(
                            "sjiswrap: GetCommandLineA(): Expected space after quote, got '{}'",
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
    state.cmdline = Some(unsafe { CString::from_vec_with_nul_unchecked(cmdline) });
    PCSTR(state.cmdline.as_ref().unwrap().as_ptr() as *const u8)
}

/// `GetCommandLineW` hook. Currently unsupported.
extern "stdcall" fn hook_GetCommandLineW() -> PCSTR {
    fail!("sjiswrap: GetCommandLineW() is not supported");
}

/// Read a file into memory and encode it as Shift JIS.
fn encode_file(handle: HANDLE, path: &Path) {
    let state = unsafe { GLOBAL_STATE.assume_init_mut() };
    state.file_handles.insert(handle.0, FileHandle { path: path.to_path_buf(), pos: 0 });
    let Entry::Vacant(entry) = state.encoded_files.entry(path.to_path_buf()) else {
        debug_println!("File already cached: {}", path.display());
        return;
    };

    let mut filesize_high = 0u32;
    let mut filesize = unsafe { GetFileSize(handle, Some(&mut filesize_high)) } as u64;
    filesize |= (filesize_high as u64) << 32;
    if filesize >= u32::MAX as u64 {
        return;
    }

    // Include a null terminator for MapViewOfFile
    let mut data = vec![0u8; filesize as usize + 1];
    let mut bytes_read = 0u32;
    if unsafe {
        let slice = &mut data[..filesize as usize];
        ReadFile(handle, Some(slice), Some(&mut bytes_read), None)
    }
    .is_err()
        || bytes_read != filesize as u32
    {
        eprintln!("sjiswrap: Failed to read file {}", path.display());
        return;
    }

    let str = match std::str::from_utf8(&data) {
        Ok(str) => str,
        Err(e) => fail!("sjiswrap: File {} is not valid UTF-8: {}", path.display(), e),
    };
    let (encoded, _, error) = SHIFT_JIS.encode(str);
    if error {
        eprintln!("sjiswrap: File {} contains Shift JIS encoding errors", path.display());
    }
    match encoded {
        Cow::Borrowed(_) => {
            // No modifications were made, use the original data
            entry.insert(Pin::new(data.into_boxed_slice()));
        }
        Cow::Owned(data) => {
            entry.insert(Pin::new(data.into_boxed_slice()));
        }
    }
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

    let path = PathBuf::from(
        unsafe { CStr::from_ptr(lpFileName.as_ptr() as *const c_char) }
            .to_str()
            .expect("CreateFileA(): Path is not valid UTF-8"),
    );
    if !ret.is_invalid() && dwDesiredAccess == GENERIC_READ && is_text_file(&path) {
        encode_file(ret, &path);
    }
    debug_println!(
        "CreateFileA({}, {:#X}) = {:#X}",
        path.display(),
        dwDesiredAccess.0,
        ret.0 as u32
    );
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
    fail!("sjiswrap: CreateFileW() is not supported");
}

/// `GetFileSize` hook. If the file was read into memory, return that size instead.
extern "stdcall" fn hook_GetFileSize(hFile: HANDLE, lpFileSizeHigh: *mut u32) -> u32 {
    if !hFile.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((handle, data)) = state.file_by_handle(hFile) {
            let _ = handle;
            let file_size = data.len() as u32 - 1 /* null terminator */;
            debug_println!("OVERRIDE: GetFileSize({}) = {:#X}", handle.path.display(), file_size);
            return file_size;
        }
    }

    let ret = unsafe { GetFileSize(hFile, Some(lpFileSizeHigh)) };
    debug_println!("GetFileSize({:p}, {:?}) = {:#X}", hFile.0, lpFileSizeHigh, ret);
    ret
}

/// `CloseHandle` hook. If the file was read into memory, free it.
extern "stdcall" fn hook_CloseHandle(hObject: HANDLE) -> BOOL {
    if !hObject.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some(handle) = state.file_handles.remove(&hObject.0) {
            let _ = handle;
            debug_println!("File handle removed: {:p} ({})", hObject.0, handle.path.display());
            // Purposefully leave the file data itself in the cache.
            // mwcceppc in particular will read the same file multiple times.
        }
        if let Some(_mapping) = state.file_mapping_handles.remove(&hObject.0) {
            debug_println!("File mapping handle removed: {:p}", hObject.0);
        }
    }

    let ret = unsafe { CloseHandle(hObject) }.is_ok();
    debug_println!("CloseHandle({:p}) = {}", hObject.0, ret);
    ret.into()
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
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((handle, data)) = state.file_by_handle(hFile) {
            let file_size = data.len() as u64 - 1 /* null terminator */;
            let count = min(
                nNumberOfBytesToRead,
                u32::try_from(file_size - handle.pos).unwrap_or(u32::MAX),
            );
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr().offset(handle.pos as isize),
                    lpBuffer as *mut u8,
                    count as usize,
                );
            }
            handle.pos += count as u64;
            if !lpNumberOfBytesRead.is_null() {
                unsafe { *lpNumberOfBytesRead = count };
            }
            debug_println!(
                "OVERRIDE: ReadFile({:p}, {:?}, {:#X}, {:?}) = {:#X}",
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
            Some(std::slice::from_raw_parts_mut(
                lpBuffer as *mut u8,
                nNumberOfBytesToRead as usize,
            )),
            Some(lpNumberOfBytesRead),
            Some(lpOverlapped),
        )
    }
    .is_ok();
    debug_println!(
        "ReadFile({:p}, {:?}, {:#X}, {:?}) = {}",
        hFile.0,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        ret
    );
    ret.into()
}

/// `ReadFileEx` hook. Currently unsupported.
extern "stdcall" fn hook_ReadFileEx(
    hFile: HANDLE,
    lpBuffer: *mut c_void,
    nNumberOfBytesToRead: u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL {
    if !hFile.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((_handle, _data)) = state.file_by_handle(hFile) {
            fail!("sjiswrap: ReadFileEx() is not supported");
        }
    }

    // Pass through un-encoded files
    let ret = unsafe {
        ReadFileEx(
            hFile,
            if lpBuffer.is_null() {
                None
            } else {
                Some(std::slice::from_raw_parts_mut(
                    lpBuffer as *mut u8,
                    nNumberOfBytesToRead as usize,
                ))
            },
            lpOverlapped,
            lpCompletionRoutine,
        )
    }
    .is_ok();
    debug_println!(
        "ReadFileEx({:p}, {:?}, {:#X}, {:?}, {:?}) = {}",
        hFile.0,
        lpBuffer,
        nNumberOfBytesToRead,
        lpOverlapped,
        lpCompletionRoutine,
        ret
    );
    ret.into()
}

/// `CreateFileMappingA` hook. Currently unsupported.
extern "stdcall" fn hook_CreateFileMappingA(
    hFile: HANDLE,
    lpAttributes: *const SECURITY_ATTRIBUTES,
    flProtect: PAGE_PROTECTION_FLAGS,
    dwMaximumSizeHigh: u32,
    dwMaximumSizeLow: u32,
    lpName: PCSTR,
) -> HANDLE {
    let ret = unsafe {
        CreateFileMappingA(
            hFile,
            if lpAttributes.is_null() { None } else { Some(lpAttributes) },
            flProtect,
            dwMaximumSizeHigh,
            dwMaximumSizeLow,
            lpName,
        )
    }
    .unwrap_or(INVALID_HANDLE_VALUE);

    if !hFile.is_invalid() && !ret.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((_handle, _data)) = state.file_by_handle(hFile) {
            if let Some(existing) = state.file_mapping_handles.insert(ret.0, hFile) {
                fail!(
                    "sjiswrap: CreateFileMappingA({:p}, {:?}, {:#X}, {:#X}, {:#X}, {:?}): Mapping already exists for {:p}",
                    hFile.0,
                    lpAttributes,
                    flProtect.0,
                    dwMaximumSizeHigh,
                    dwMaximumSizeLow,
                    lpName,
                    existing.0
                );
            }
            debug_println!(
                "OVERRIDE CreateFileMappingA({:p}, {:?}, {:#X}, {:#X}, {:#X}, {:?}) = {:p}",
                hFile.0,
                lpAttributes,
                flProtect.0,
                dwMaximumSizeHigh,
                dwMaximumSizeLow,
                lpName,
                ret.0
            );
            return ret;
        }
    }

    debug_println!(
        "CreateFileMappingA({:p}, {:?}, {:#X}, {:#X}, {:#X}, {:?}) = {:p}",
        hFile.0,
        lpAttributes,
        flProtect.0,
        dwMaximumSizeHigh,
        dwMaximumSizeLow,
        lpName,
        ret.0
    );
    ret
}

/// `CreateFileMappingW` hook. Currently unsupported.
extern "stdcall" fn hook_CreateFileMappingW(
    _hFile: HANDLE,
    _lpAttributes: *const SECURITY_ATTRIBUTES,
    _flProtect: u32,
    _dwMaximumSizeHigh: u32,
    _dwMaximumSizeLow: u32,
    _lpName: PCWSTR,
) -> HANDLE {
    fail!("sjiswrap: CreateFileMappingW() is not supported");
}

/// `OpenFileMappingA` hook. Currently unsupported.
extern "stdcall" fn hook_OpenFileMappingA(
    _dwDesiredAccess: u32,
    _bInheritHandle: BOOL,
    _lpName: PCSTR,
) -> HANDLE {
    fail!("sjiswrap: OpenFileMappingA() is not supported");
}

/// `OpenFileMappingW` hook. Currently unsupported.
extern "stdcall" fn hook_OpenFileMappingW(
    _dwDesiredAccess: u32,
    _bInheritHandle: BOOL,
    _lpName: PCWSTR,
) -> HANDLE {
    fail!("sjiswrap: OpenFileMappingW() is not supported");
}

/// `MapViewOfFile` hook. If the file was read into memory, return that instead.
extern "stdcall" fn hook_MapViewOfFile(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: FILE_MAP,
    dwFileOffsetHigh: u32,
    dwFileOffsetLow: u32,
    dwNumberOfBytesToMap: usize,
) -> *mut c_void {
    if !hFileMappingObject.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((handle, data)) = state.file_by_mapping_handle(hFileMappingObject) {
            if dwDesiredAccess.contains(FILE_MAP_WRITE)
                || dwDesiredAccess.contains(FILE_MAP_ALL_ACCESS)
            {
                fail!("sjiswrap: MapViewOfFile(): Write access to encoded file is not supported");
            }
            let offset = (dwFileOffsetHigh as u64) << 32 | dwFileOffsetLow as u64;
            if offset > 0 {
                fail!(
                    "sjiswrap: MapViewOfFile({}): Offset is not supported ({})",
                    handle.path.display(),
                    offset
                );
            }
            if dwNumberOfBytesToMap != data.len() - 1
            /* null terminator */
            {
                fail!(
                    "sjiswrap: MapViewOfFile({}): Mapping size mismatch ({} != {})",
                    handle.path.display(),
                    dwNumberOfBytesToMap,
                    data.len() - 1
                );
            }
            let ptr = data.as_ptr() as *mut c_void;
            debug_println!(
                "OVERRIDE MapViewOfFile({:p}, {:#X}, {:#X}, {:#X}, {:#X}) = {:p}",
                hFileMappingObject.0,
                dwDesiredAccess.0,
                dwFileOffsetHigh,
                dwFileOffsetLow,
                dwNumberOfBytesToMap,
                ptr
            );
            state.view_to_mapping.insert(ptr, hFileMappingObject);
            return ptr;
        }
    }

    let ret = unsafe {
        MapViewOfFile(
            hFileMappingObject,
            dwDesiredAccess,
            dwFileOffsetHigh,
            dwFileOffsetLow,
            dwNumberOfBytesToMap,
        )
    };
    debug_println!(
        "MapViewOfFile({:p}, {:#X}, {:#X}, {:#X}, {:#X}) = {:p}",
        hFileMappingObject.0,
        dwDesiredAccess.0,
        dwFileOffsetHigh,
        dwFileOffsetLow,
        dwNumberOfBytesToMap,
        ret.Value
    );
    ret.Value
}

/// `MapViewOfFileEx` hook. Currently unsupported.
extern "stdcall" fn hook_MapViewOfFileEx(
    _hFileMappingObject: HANDLE,
    _dwDesiredAccess: FILE_MAP,
    _dwFileOffsetHigh: u32,
    _dwFileOffsetLow: u32,
    _dwNumberOfBytesToMap: usize,
    _lpBaseAddress: *mut c_void,
) -> *mut c_void {
    fail!("sjiswrap: MapViewOfFileEx() is not supported");
}

/// `UnmapViewOfFile` hook. If the file was read into memory, remove the mapping.
extern "stdcall" fn hook_UnmapViewOfFile(lpBaseAddress: *mut c_void) -> BOOL {
    let state = unsafe { GLOBAL_STATE.assume_init_mut() };
    if let Some(_handle) = state.view_to_mapping.remove(&lpBaseAddress) {
        debug_println!("OVERRIDE UnmapViewOfFile({:p})", lpBaseAddress);
        return true.into();
    }

    let ret =
        unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: lpBaseAddress }) }.is_ok();
    debug_println!("UnmapViewOfFile({:p}) = {}", lpBaseAddress, ret);
    ret.into()
}

/// `SetFilePointer` hook. If the file was read into memory, set the position in that instead.
extern "stdcall" fn hook_SetFilePointer(
    hFile: HANDLE,
    lDistanceToMove: i32,
    lpDistanceToMoveHigh: *mut i32,
    dwMoveMethod: SET_FILE_POINTER_MOVE_METHOD,
) -> u32 {
    if !hFile.is_invalid() {
        let state = unsafe { GLOBAL_STATE.assume_init_mut() };
        if let Some((handle, data)) = state.file_by_handle(hFile) {
            let distance_to_move_high =
                if lpDistanceToMoveHigh.is_null() { 0 } else { unsafe { *lpDistanceToMoveHigh } };
            let distance_to_move = lDistanceToMove as i64 | (distance_to_move_high as i64) << 32;
            let file_size = data.len() as u64 - 1 /* null terminator */;
            let pos = min(
                match dwMoveMethod {
                    FILE_BEGIN => distance_to_move as u64,
                    FILE_CURRENT => handle.pos.saturating_add_signed(distance_to_move),
                    FILE_END => file_size.saturating_add_signed(distance_to_move),
                    _ => fail!("sjiswrap: SetFilePointer(): Unsupported move method {:#X}", dwMoveMethod.0),
                },
                file_size,
            );
            handle.pos = pos;
            debug_println!(
                "OVERRIDE SetFilePointer({:p}, {:#X}, {:?}, {}) = {:#X}",
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
        "SetFilePointer({:p}, {:#X}, {:?}, {}) = {:#X}",
        hFile.0,
        lDistanceToMove,
        lpDistanceToMoveHigh,
        dwMoveMethod.0,
        ret
    );
    ret
}

/// `IsDBCSLeadByte` hook. This normally uses the system codepage, override with Shift JIS behavior.
extern "stdcall" fn hook_IsDBCSLeadByte(TestChar: u8) -> BOOL { (TestChar & 0x80 != 0).into() }

fn slice_of<T>(ptr: *const T, len: i32) -> &'static [T]
where T: Copy + Zero {
    if ptr.is_null() {
        return &[];
    }
    if len < 0 {
        // Null terminated
        let mut len = 0;
        while !unsafe { *ptr.offset(len) }.is_zero() {
            len += 1;
        }
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    }
}

fn slice_of_mut<T>(ptr: *mut T, len: i32) -> Option<&'static mut [T]>
where T: Copy + Zero {
    if ptr.is_null() || len < 0 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) })
}

/// `MultiByteToWideChar` hook. This reimplements the conversion for Shift JIS, using the pre-XP
/// behavior of failing on illegal code points. MWCC 3.0 relies on this behavior.
/// See https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
extern "stdcall" fn hook_MultiByteToWideChar(
    CodePage: u32,
    dwFlags: MULTI_BYTE_TO_WIDE_CHAR_FLAGS,
    lpMultiByteStr: PCSTR,
    cbMultiByte: i32,
    lpWideCharStr: *mut u16,
    cchWideChar: i32,
) -> i32 {
    let mb_str = slice_of(lpMultiByteStr.as_ptr(), cbMultiByte);
    let mut wide_str = slice_of_mut(lpWideCharStr, cchWideChar);
    let decoder = match CodePage {
        0 => UTF_8,
        932 => SHIFT_JIS,
        _ => {
            // Try to pass through
            let ret =
                unsafe { MultiByteToWideChar(CodePage, dwFlags, mb_str, wide_str.as_deref_mut()) };
            debug_println!(
                "MultiByteToWideChar({}, {:#X}, {:?} ({:X?}), {:?}) = {} ({:?})",
                CodePage,
                dwFlags.0,
                mb_str,
                lpMultiByteStr,
                wide_str,
                ret,
                unsafe { GetLastError() }
            );
            return ret;
        }
    };
    let (decoded, _, err) = decoder.decode(mb_str);
    let ret = if err {
        unsafe { SetLastError(ERROR_NO_UNICODE_TRANSLATION) };
        0
    } else {
        match wide_str.as_deref_mut() {
            None => {
                unsafe { SetLastError(ERROR_SUCCESS) };
                decoded.encode_utf16().count() as i32
            }
            Some(out) => {
                let mut out = out.iter_mut();
                let mut written = 0;
                for mut c in decoded.encode_utf16() {
                    if c == 0xFFFD && CodePage == 932 {
                        // CP-932 replacement character
                        c = 0x30FB;
                    }
                    if let Some(out) = out.next() {
                        *out = c;
                        written += 1;
                    } else {
                        // Insufficient buffer
                        written = -1;
                        break;
                    }
                }
                if written < 0 {
                    unsafe { SetLastError(ERROR_INSUFFICIENT_BUFFER) };
                    decoded.encode_utf16().count() as i32
                } else {
                    unsafe { SetLastError(ERROR_SUCCESS) };
                    written
                }
            }
        }
    };
    debug_println!(
        "OVERRIDE MultiByteToWideChar({}, {:#X}, {:?} ({:X?}), {:?}) = {} ({:?})",
        CodePage,
        dwFlags.0,
        decoded,
        mb_str,
        wide_str,
        ret,
        unsafe { GetLastError() }
    );
    ret
}

/// `GetACP` hook. Return the Shift JIS codepage.
extern "stdcall" fn hook_GetACP() -> u32 {
    debug_println!("OVERRIDE GetACP() = 932");
    932
}

/// `GetModuleFileNameA` hook. Return the absolute path of the executable.
extern "stdcall" fn hook_GetModuleFileNameA(
    hModule: HMODULE,
    lpFilename: *mut c_char,
    nSize: u32,
) -> u32 {
    let _ = hModule; // ?

    let state = unsafe { GLOBAL_STATE.assume_init_ref() };
    let path_bytes = state.exe_path.as_bytes(); // Without nul terminator
    let ret = min(nSize.saturating_sub(1), path_bytes.len() as u32);
    if !lpFilename.is_null() && ret > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(path_bytes.as_ptr(), lpFilename as *mut u8, ret as usize);
        }
        unsafe { *lpFilename.offset(ret as isize) = 0 };
    }
    #[cfg(feature = "debug")]
    {
        let slice = unsafe { std::slice::from_raw_parts(lpFilename as *const u8, ret as usize) };
        let str = unsafe { std::str::from_utf8_unchecked(slice) };
        eprintln!(
            "OVERRIDE GetModuleFileNameA({:p}, {:?}, {:#X}) = {:#X} ({})",
            hModule.0, lpFilename, nSize, ret, str
        );
    }
    if ret < path_bytes.len() as u32 {
        unsafe { SetLastError(ERROR_INSUFFICIENT_BUFFER) };
    }
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
