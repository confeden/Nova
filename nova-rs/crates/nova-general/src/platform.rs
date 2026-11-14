use crate::{Result, transport::Binding};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    path::Path,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, SOCKADDR_IN},
    Storage::FileSystem::*,
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

#[derive(Clone, Copy)]
pub(crate) struct Physical {
    pub binding: Binding,
    pub network: u64,
}
pub(crate) fn physical() -> Result<Option<Physical>> {
    let mut bytes = 16384u32;
    for _ in 0..3 {
        let mut buffer = vec![0u64; (bytes as usize + 7) / 8];
        let start = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let rc = unsafe {
            GetAdaptersAddresses(AF_INET as u32, GAA_FLAG_INCLUDE_GATEWAYS, std::ptr::null(), start, &mut bytes)
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            return Err(format!("adapter enumeration: {rc}").into());
        }
        let mut current = start;
        let mut selected = Vec::new();
        while !current.is_null() {
            let a = unsafe { &*current };
            current = a.Next;
            if a.OperStatus != 1 || !matches!(a.IfType, 6 | 71) || a.FirstGatewayAddress.is_null() {
                continue;
            }
            let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
            row.InterfaceIndex = index;
            if unsafe { GetIfEntry2(&mut row) } != 0 || row.InterfaceAndOperStatusFlags._bitfield & 1 == 0 {
                continue;
            }
            let mut address = a.FirstUnicastAddress;
            while !address.is_null() {
                let u = unsafe { &*address };
                address = u.Next;
                if u.Address.lpSockaddr.is_null() || unsafe { (*u.Address.lpSockaddr).sa_family } != AF_INET {
                    continue;
                }
                let v = unsafe { &*(u.Address.lpSockaddr.cast::<SOCKADDR_IN>()) };
                let raw = unsafe { v.sin_addr.S_un.S_addr };
                let ip = Ipv4Addr::from(raw.to_ne_bytes());
                if ip.is_unspecified() || ip.is_link_local() || ip.is_loopback() {
                    continue;
                }
                let mut hash = DefaultHasher::new();
                a.NetworkGuid.data1.hash(&mut hash);
                a.NetworkGuid.data2.hash(&mut hash);
                a.NetworkGuid.data3.hash(&mut hash);
                a.NetworkGuid.data4.hash(&mut hash);
                ip.hash(&mut hash);
                index.hash(&mut hash);
                selected.push((
                    a.Ipv4Metric,
                    Physical { binding: Binding { ip, index, port: 0 }, network: hash.finish() },
                ));
                break;
            }
        }
        selected.sort_by_key(|(metric, p)| (*metric, p.binding.index));
        return Ok(selected.first().map(|(_, p)| *p));
    }
    Err("adapter table kept changing".into())
}
pub(crate) fn octets(index: u32) -> Result<u64> {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = index;
    let rc = unsafe { GetIfEntry2(&mut row) };
    if rc != 0 {
        return Err(format!("interface counters: {rc}").into());
    }
    Ok(row.InOctets.saturating_add(row.OutOctets))
}
pub(crate) fn watch_parent(pid: u32) -> Result<()> {
    if pid == 0 {
        return Err("parent PID is missing".into());
    }
    let h = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if h.is_null() {
        return Err("cannot observe Nova lifetime".into());
    }
    let raw = h as usize;
    std::thread::spawn(move || {
        let result = unsafe { WaitForSingleObject(raw as HANDLE, u32::MAX) };
        unsafe { CloseHandle(raw as HANDLE) };
        std::process::exit(if result == WAIT_OBJECT_0 { 0 } else { 1 });
    });
    Ok(())
}
pub(crate) fn foreign_test() -> Result<bool> {
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h == INVALID_HANDLE_VALUE {
        return Err("cannot check strategy-test ownership".into());
    }
    let mut item: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    item.dwSize = std::mem::size_of_val(&item) as u32;
    let mut found = false;
    let mut ok = unsafe { Process32FirstW(h, &mut item) };
    while ok != 0 {
        let end = item.szExeFile.iter().position(|&n| n == 0).unwrap_or(item.szExeFile.len());
        let name = String::from_utf16_lossy(&item.szExeFile[..end]).to_ascii_lowercase();
        if matches!(name.as_str(), "winws_test.exe" | "winws-bench.exe") {
            found = true;
            break;
        }
        ok = unsafe { Process32NextW(h, &mut item) };
    }
    unsafe { CloseHandle(h) };
    Ok(found)
}
pub(crate) fn atomic_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let temporary = path.with_extension("new");
    std::fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    let wide = |p: &Path| p.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let from = wide(&temporary);
    let to = wide(path);
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
