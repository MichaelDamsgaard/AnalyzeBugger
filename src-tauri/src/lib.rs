//! AnalyzeBugger Tauri Application
//! AI-Powered Reverse Engineering Platform

mod engine;
mod intel_pt;
mod mcp_api;

use std::sync::{Arc, Mutex};
use tauri::State;
use serde_json::json;
use engine::session::SessionManager;
use intel_pt::IntelPTManager;

/// Application state
pub struct AppState {
    session_manager: Mutex<SessionManager>,
    intel_pt_manager: Mutex<IntelPTManager>,
    mcp_state: Arc<mcp_api::McpApiState>,
}

// ============================================================================
// Tauri Commands - Debug Session
// ============================================================================

#[tauri::command]
fn get_status(state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;
    let status = manager.get_status();

    let active_session = manager.get_active_session().map(|s| {
        json!({
            "id": s.id,
            "target_path": s.target_path,
            "state": format!("{:?}", s.state).to_lowercase(),
            "process_id": s.process_id,
            "thread_id": s.thread_id,
            "current_ip": s.get_current_ip().ok().map(|ip| format!("0x{:016x}", ip)),
            "module_count": s.get_module_count().ok(),
            "breakpoint_count": s.get_detailed_status().ok().map(|s| s.breakpoint_count)
        })
    });

    let result = json!({
        "dll_loaded": status.dll_loaded,
        "dll_version": status.dll_version,
        "session_count": status.session_count,
        "session": active_session
    });

    Ok(result.to_string())
}

#[tauri::command]
fn launch_target(path: String, state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    // Create session
    let session_id = manager.create_session(&path)?;

    // Start debugging
    if let Some(session) = manager.get_session_mut(&session_id) {
        session.start()?;
    }

    // Get updated status
    drop(manager);
    get_status(state)
}

#[tauri::command]
fn stop_session(state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session_mut() {
        session.stop()?;
    }

    Ok(json!({"status": "stopped"}).to_string())
}

#[tauri::command]
fn continue_execution(state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session_mut() {
        session.continue_execution()?;
    }

    Ok(json!({"status": "running"}).to_string())
}

#[tauri::command]
fn pause_execution(state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session_mut() {
        session.pause()?;
    }

    Ok(json!({"status": "paused"}).to_string())
}

#[tauri::command]
fn step_into(state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session_mut() {
        session.step_into()?;
    }

    Ok(json!({"status": "stepped"}).to_string())
}

#[tauri::command]
fn step_over(state: State<AppState>) -> Result<String, String> {
    let mut manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session_mut() {
        session.step_over()?;
    }

    Ok(json!({"status": "stepped"}).to_string())
}

// ============================================================================
// Tauri Commands - Registers
// ============================================================================

#[tauri::command]
fn get_registers(state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session() {
        let regs = session.get_registers()?;

        // Copy to avoid packed struct issues
        let rax = regs.rax;
        let rbx = regs.rbx;
        let rcx = regs.rcx;
        let rdx = regs.rdx;
        let rsi = regs.rsi;
        let rdi = regs.rdi;
        let rsp = regs.rsp;
        let rbp = regs.rbp;
        let rip = regs.rip;
        let r8 = regs.r8;
        let r9 = regs.r9;
        let r10 = regs.r10;
        let r11 = regs.r11;
        let r12 = regs.r12;
        let r13 = regs.r13;
        let r14 = regs.r14;
        let r15 = regs.r15;
        let eflags = regs.eflags;

        let result = json!({
            "rax": format!("0x{:016x}", rax),
            "rbx": format!("0x{:016x}", rbx),
            "rcx": format!("0x{:016x}", rcx),
            "rdx": format!("0x{:016x}", rdx),
            "rsi": format!("0x{:016x}", rsi),
            "rdi": format!("0x{:016x}", rdi),
            "rsp": format!("0x{:016x}", rsp),
            "rbp": format!("0x{:016x}", rbp),
            "rip": format!("0x{:016x}", rip),
            "r8": format!("0x{:016x}", r8),
            "r9": format!("0x{:016x}", r9),
            "r10": format!("0x{:016x}", r10),
            "r11": format!("0x{:016x}", r11),
            "r12": format!("0x{:016x}", r12),
            "r13": format!("0x{:016x}", r13),
            "r14": format!("0x{:016x}", r14),
            "r15": format!("0x{:016x}", r15),
            "eflags": format!("0x{:08x}", eflags)
        });

        Ok(result.to_string())
    } else {
        Err("No active session".to_string())
    }
}

// ============================================================================
// Tauri Commands - Memory
// ============================================================================

#[tauri::command]
fn read_memory(address: String, length: u32, state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    let addr = parse_hex_address(&address).ok_or("Invalid address")?;

    if let Some(session) = manager.get_active_session() {
        let data = session.read_memory(addr, length)?;

        let hex_string = data.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let result = json!({
            "address": address,
            "length": data.len(),
            "data": hex_string
        });

        Ok(result.to_string())
    } else {
        Err("No active session".to_string())
    }
}

// ============================================================================
// Tauri Commands - Modules
// ============================================================================

#[tauri::command]
fn get_modules(state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session() {
        let count = session.get_module_count()?;
        let mut modules = Vec::new();

        for i in 0..count {
            if let Ok(info) = session.get_module_info(i) {
                let base_address = info.base_address;
                let size = info.size;
                let entry_point = info.entry_point;
                let name = info.get_name();

                modules.push(json!({
                    "name": name,
                    "base": format!("0x{:016x}", base_address),
                    "size": size,
                    "entry": format!("0x{:016x}", entry_point)
                }));
            }
        }

        let result = json!({
            "count": count,
            "modules": modules
        });

        Ok(result.to_string())
    } else {
        Err("No active session".to_string())
    }
}

// ============================================================================
// Tauri Commands - Disassembly
// ============================================================================

#[tauri::command]
fn disassemble(address: String, length: u32, state: State<AppState>) -> Result<String, String> {
    use capstone::prelude::*;

    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;
    let addr = parse_hex_address(&address).ok_or("Invalid address")?;

    if let Some(session) = manager.get_active_session() {
        let data = session.read_memory(addr, length)?;

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .map_err(|e| e.to_string())?;

        let insns = cs.disasm_all(&data, addr).map_err(|e| e.to_string())?;

        let instructions: Vec<_> = insns.iter().map(|i| {
            json!({
                "address": format!("0x{:x}", i.address()),
                "bytes": i.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                "mnemonic": i.mnemonic().unwrap_or("???"),
                "op_str": i.op_str().unwrap_or("")
            })
        }).collect();

        let result = json!({
            "address": address,
            "count": instructions.len(),
            "instructions": instructions
        });

        Ok(result.to_string())
    } else {
        Err("No active session".to_string())
    }
}

// ============================================================================
// Tauri Commands - Breakpoints
// ============================================================================

#[tauri::command]
fn set_breakpoint(address: String, bp_type: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;
    let addr = parse_hex_address(&address).ok_or("Invalid address")?;

    let bp_type_code = match bp_type.as_str() {
        "software" => 0,
        "hardware_exec" => 1,
        "hardware_write" => 2,
        "hardware_rw" => 3,
        _ => 0,
    };

    if let Some(session) = manager.get_active_session() {
        let bp_id = session.set_breakpoint(addr, bp_type_code)?;

        let result = json!({
            "status": "breakpoint_set",
            "bp_id": bp_id,
            "address": address
        });

        Ok(result.to_string())
    } else {
        Err("No active session".to_string())
    }
}

#[tauri::command]
fn remove_breakpoint(bp_id: i32, state: State<AppState>) -> Result<String, String> {
    let manager = state.session_manager.lock().map_err(|e| e.to_string())?;

    if let Some(session) = manager.get_active_session() {
        session.remove_breakpoint(bp_id)?;

        Ok(json!({"status": "removed", "bp_id": bp_id}).to_string())
    } else {
        Err("No active session".to_string())
    }
}

// ============================================================================
// Tauri Commands - Static Analysis (no debugging, just file analysis)
// ============================================================================

#[tauri::command]
fn analyze_file(path: String) -> Result<String, String> {
    use capstone::prelude::*;
    use std::fs;

    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = data.len();

    // Detect file type and set up disassembler
    let (arch_mode, base_address, arch_name) = detect_file_type(&data, &path);

    // Create Capstone disassembler
    let cs = match arch_mode {
        ArchMode::Mode16 => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode16)
                .build()
                .map_err(|e| e.to_string())?
        }
        ArchMode::Mode32 => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .map_err(|e| e.to_string())?
        }
        ArchMode::Mode64 => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .map_err(|e| e.to_string())?
        }
    };

    // Disassemble
    let insns = cs.disasm_all(&data, base_address).map_err(|e| e.to_string())?;

    let instructions: Vec<_> = insns.iter().take(2000).map(|i| {
        json!({
            "address": format!("0x{:04X}", i.address()),
            "bytes": i.bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
            "mnemonic": i.mnemonic().unwrap_or("???"),
            "op_str": i.op_str().unwrap_or("")
        })
    }).collect();

    // Extract strings
    let strings = extract_strings(&data);

    // Calculate entropy
    let entropy = calculate_entropy(&data);

    // Analyze instructions for patterns
    let analysis = analyze_instructions(&insns, arch_mode);

    // Extract IOCs from strings
    let iocs = extract_iocs(&strings);

    // Detect MITRE techniques
    let mitre_techniques = detect_mitre_techniques(&insns, &strings, arch_mode);

    // Detect crypto patterns
    let crypto = detect_crypto_patterns(&data);

    // Initial register state based on architecture
    let initial_registers = get_initial_registers(arch_mode, base_address);

    // Parse PE structures
    let sections = parse_pe_sections(&data);
    let imports = parse_pe_imports(&data);
    let exports = parse_pe_exports(&data);

    // Generate raw hex dump for crypto analysis
    let raw_bytes = generate_hex_dump(&data, base_address);

    // Detect patterns
    let file_info = json!({
        "name": std::path::Path::new(&path).file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
        "size": file_size,
        "arch": arch_name,
        "base_address": format!("0x{:04X}", base_address),
        "entropy": format!("{:.2}", entropy),
        "is_packed": entropy > 7.0
    });

    let result = json!({
        "file_info": file_info,
        "instructions": instructions,
        "instruction_count": insns.len(),
        "strings": strings,
        "string_count": strings.len(),
        "analysis": analysis,
        "iocs": iocs,
        "mitre_techniques": mitre_techniques,
        "crypto": crypto,
        "initial_registers": initial_registers,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "raw_bytes": raw_bytes
    });

    Ok(result.to_string())
}

#[derive(Clone, Copy)]
enum ArchMode {
    Mode16,
    Mode32,
    Mode64,
}

fn detect_file_type(data: &[u8], path: &str) -> (ArchMode, u64, &'static str) {
    let path_lower = path.to_lowercase();

    // COM file - 16-bit, loads at 0x100
    if path_lower.ends_with(".com") {
        return (ArchMode::Mode16, 0x100, "x86-16 (DOS COM)");
    }

    // Check for MZ header (DOS/PE)
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        // Check for PE
        if data.len() >= 64 {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if data.len() > pe_offset + 6 && &data[pe_offset..pe_offset+4] == b"PE\x00\x00" {
                let machine = u16::from_le_bytes([data[pe_offset+4], data[pe_offset+5]]);
                match machine {
                    0x8664 => return (ArchMode::Mode64, 0x140000000, "x86-64 (PE)"),
                    0x014c => return (ArchMode::Mode32, 0x400000, "x86-32 (PE)"),
                    _ => {}
                }
            }
        }
        // DOS EXE
        return (ArchMode::Mode16, 0x100, "x86-16 (DOS EXE)");
    }

    // ELF
    if data.len() >= 5 && &data[0..4] == b"\x7FELF" {
        match data[4] {
            2 => return (ArchMode::Mode64, 0x400000, "x86-64 (ELF)"),
            1 => return (ArchMode::Mode32, 0x8048000, "x86-32 (ELF)"),
            _ => {}
        }
    }

    // Default to 32-bit
    (ArchMode::Mode32, 0x0, "Unknown (x86-32)")
}

fn extract_strings(data: &[u8]) -> Vec<serde_json::Value> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7F {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte);
        } else {
            if current.len() >= 4 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(json!({
                        "offset": format!("0x{:04X}", start_offset),
                        "value": s,
                        "length": s.len()
                    }));
                }
            }
            current.clear();
        }
    }

    // Don't forget last string
    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(json!({
                "offset": format!("0x{:04X}", start_offset),
                "value": s,
                "length": s.len()
            }));
        }
    }

    strings.into_iter().take(100).collect()
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Generate hex dump with addresses for crypto analysis
fn generate_hex_dump(data: &[u8], base_address: u64) -> String {
    let mut lines = Vec::new();

    // For small files, dump everything; for larger files, dump key regions
    let regions: Vec<(usize, usize, &str)> = if data.len() <= 2048 {
        vec![(0, data.len(), "Full dump")]
    } else {
        // Dump entry point area and data section hints
        vec![
            (0, 512.min(data.len()), "Entry region"),
            (data.len().saturating_sub(512), data.len(), "End region"),
        ]
    };

    for (start, end, label) in regions {
        lines.push(format!("--- {} (0x{:04X}-0x{:04X}) ---", label, base_address + start as u64, base_address + end as u64 - 1));

        for offset in (start..end).step_by(16) {
            let addr = base_address + offset as u64;
            let end_idx = (offset + 16).min(end);
            let bytes = &data[offset..end_idx];

            // Hex part
            let hex: String = bytes.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");

            // ASCII part
            let ascii: String = bytes.iter()
                .map(|&b| if b >= 0x20 && b < 0x7F { b as char } else { '.' })
                .collect();

            lines.push(format!("{:04X}: {:<48} |{}|", addr, hex, ascii));
        }
    }

    lines.join("\n")
}

// ============================================================================
// Deep Analysis Functions
// ============================================================================

fn analyze_instructions(insns: &capstone::Instructions, arch_mode: ArchMode) -> serde_json::Value {
    let mut call_count = 0;
    let mut jump_count = 0;
    let mut int_count = 0;
    let mut syscall_count = 0;
    let mut push_count = 0;
    let mut pop_count = 0;
    let mut nop_count = 0;
    let mut xor_self_count = 0;  // Self-XOR often used for zeroing or decryption
    let mut suspicious_patterns: Vec<serde_json::Value> = Vec::new();
    let mut interrupts: Vec<serde_json::Value> = Vec::new();

    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
        let operands = insn.op_str().unwrap_or("");

        match mnemonic.as_str() {
            "call" => call_count += 1,
            "jmp" | "je" | "jne" | "jz" | "jnz" | "ja" | "jb" | "jg" | "jl" | "jae" | "jbe" | "jge" | "jle" => jump_count += 1,
            "push" => push_count += 1,
            "pop" => pop_count += 1,
            "nop" => nop_count += 1,
            "syscall" | "sysenter" => syscall_count += 1,
            "int" => {
                int_count += 1;
                // Parse interrupt number
                let int_num = operands.trim();
                let desc = match int_num {
                    "0x21" | "21h" | "0x21" => "DOS API",
                    "0x10" | "10h" => "BIOS Video",
                    "0x13" | "13h" => "BIOS Disk",
                    "0x16" | "16h" => "BIOS Keyboard",
                    "0x20" | "20h" => "DOS Terminate",
                    "0x80" | "80h" => "Linux syscall",
                    "3" | "0x3" => "Debugger breakpoint",
                    _ => "Unknown"
                };
                interrupts.push(json!({
                    "address": format!("0x{:04X}", insn.address()),
                    "interrupt": int_num,
                    "description": desc
                }));
            },
            "xor" => {
                // Check for self-XOR (reg, reg)
                let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 && parts[0] == parts[1] {
                    xor_self_count += 1;
                }
            },
            _ => {}
        }

        // Detect suspicious patterns
        // Anti-debugging: RDTSC
        if mnemonic == "rdtsc" {
            suspicious_patterns.push(json!({
                "address": format!("0x{:04X}", insn.address()),
                "type": "anti_debug",
                "pattern": "RDTSC timing check",
                "severity": "medium"
            }));
        }

        // Potential shellcode: CALL+POP for position-independent code
        if mnemonic == "call" && operands.contains("$+") {
            suspicious_patterns.push(json!({
                "address": format!("0x{:04X}", insn.address()),
                "type": "shellcode",
                "pattern": "CALL/POP GetPC",
                "severity": "high"
            }));
        }
    }

    // Detect high NOP density (potential NOP sled)
    let total = insns.len();
    if total > 0 && (nop_count as f64 / total as f64) > 0.1 {
        suspicious_patterns.push(json!({
            "address": "multiple",
            "type": "obfuscation",
            "pattern": format!("High NOP density ({:.1}%)", (nop_count as f64 / total as f64) * 100.0),
            "severity": "low"
        }));
    }

    json!({
        "total_instructions": total,
        "calls": call_count,
        "jumps": jump_count,
        "interrupts": int_count,
        "syscalls": syscall_count,
        "pushes": push_count,
        "pops": pop_count,
        "nops": nop_count,
        "self_xors": xor_self_count,
        "interrupt_details": interrupts,
        "suspicious_patterns": suspicious_patterns
    })
}

fn extract_iocs(strings: &[serde_json::Value]) -> serde_json::Value {
    let mut urls: Vec<serde_json::Value> = Vec::new();
    let mut ips: Vec<serde_json::Value> = Vec::new();
    let mut paths: Vec<serde_json::Value> = Vec::new();
    let mut registry: Vec<serde_json::Value> = Vec::new();
    let mut emails: Vec<serde_json::Value> = Vec::new();
    let mut domains: Vec<serde_json::Value> = Vec::new();

    // Regex patterns (simplified)
    let ip_pattern = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok();
    let url_pattern = regex::Regex::new(r"(https?://[^\s\x00-\x1f]+)").ok();
    let email_pattern = regex::Regex::new(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})").ok();

    for s in strings {
        if let Some(value) = s["value"].as_str() {
            let offset = s["offset"].as_str().unwrap_or("0x0");
            let lower = value.to_lowercase();

            // URLs
            if let Some(ref pat) = url_pattern {
                for cap in pat.captures_iter(value) {
                    urls.push(json!({
                        "value": &cap[1],
                        "offset": offset,
                        "defanged": cap[1].replace("http", "hxxp").replace(".", "[.]")
                    }));
                }
            }

            // IP addresses
            if let Some(ref pat) = ip_pattern {
                for cap in pat.captures_iter(value) {
                    // Filter out version numbers like 1.0.0.0
                    let ip = &cap[1];
                    let parts: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
                    if parts.len() == 4 && parts.iter().all(|&p| p <= 255) {
                        // Skip common non-IP patterns
                        if ip != "0.0.0.0" && ip != "255.255.255.255" && !ip.starts_with("0.") {
                            ips.push(json!({
                                "value": ip,
                                "offset": offset,
                                "defanged": ip.replace(".", "[.]")
                            }));
                        }
                    }
                }
            }

            // Windows paths
            if lower.contains(":\\") || lower.contains("c:\\") || lower.starts_with("\\\\") {
                paths.push(json!({
                    "value": value,
                    "offset": offset,
                    "type": if lower.starts_with("\\\\") { "UNC" } else { "local" }
                }));
            }

            // Registry keys
            if lower.contains("hkey_") || lower.contains("\\software\\") ||
               lower.contains("\\currentversion\\") || lower.contains("\\run") {
                registry.push(json!({
                    "value": value,
                    "offset": offset
                }));
            }

            // Emails
            if let Some(ref pat) = email_pattern {
                for cap in pat.captures_iter(value) {
                    emails.push(json!({
                        "value": &cap[1],
                        "offset": offset
                    }));
                }
            }

            // Domain-like strings
            if value.contains('.') && !value.contains(' ') && value.len() > 4 {
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() >= 2 {
                    let tld = parts.last().unwrap().to_lowercase();
                    if ["com", "net", "org", "io", "ru", "cn", "exe", "dll", "sys"].contains(&tld.as_str()) {
                        if tld != "exe" && tld != "dll" && tld != "sys" {
                            domains.push(json!({
                                "value": value,
                                "offset": offset,
                                "defanged": value.replace(".", "[.]")
                            }));
                        }
                    }
                }
            }
        }
    }

    json!({
        "urls": urls,
        "ips": ips,
        "paths": paths,
        "registry_keys": registry,
        "emails": emails,
        "domains": domains,
        "total": urls.len() + ips.len() + paths.len() + registry.len() + emails.len() + domains.len()
    })
}

fn detect_mitre_techniques(insns: &capstone::Instructions, strings: &[serde_json::Value], arch_mode: ArchMode) -> Vec<serde_json::Value> {
    let mut techniques: Vec<serde_json::Value> = Vec::new();

    // Collect all string values for analysis
    let string_values: Vec<&str> = strings.iter()
        .filter_map(|s| s["value"].as_str())
        .collect();
    let all_strings = string_values.join(" ").to_lowercase();

    // Check for various MITRE techniques based on patterns

    // T1059 - Command and Scripting Interpreter
    if all_strings.contains("cmd.exe") || all_strings.contains("powershell") ||
       all_strings.contains("/c ") || all_strings.contains("wscript") {
        techniques.push(json!({
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "confidence": 0.8,
            "evidence": "Command interpreter strings detected"
        }));
    }

    // T1082 - System Information Discovery
    if all_strings.contains("systeminfo") || all_strings.contains("hostname") ||
       all_strings.contains("\\system32\\") || all_strings.contains("getcomputername") {
        techniques.push(json!({
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "confidence": 0.7,
            "evidence": "System enumeration strings detected"
        }));
    }

    // T1547 - Boot or Logon Autostart Execution
    if all_strings.contains("\\run") || all_strings.contains("\\runonce") ||
       all_strings.contains("currentversion\\run") {
        techniques.push(json!({
            "id": "T1547",
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "confidence": 0.85,
            "evidence": "Autorun registry key strings detected"
        }));
    }

    // T1055 - Process Injection (check for suspicious API names)
    if all_strings.contains("virtualalloc") || all_strings.contains("writeprocessmemory") ||
       all_strings.contains("createremotethread") || all_strings.contains("ntwritevirtualmemory") {
        techniques.push(json!({
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "confidence": 0.9,
            "evidence": "Process injection API strings detected"
        }));
    }

    // T1071 - Application Layer Protocol (network indicators)
    if all_strings.contains("http://") || all_strings.contains("https://") ||
       all_strings.contains("user-agent") || all_strings.contains("socket") {
        techniques.push(json!({
            "id": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "confidence": 0.6,
            "evidence": "Network communication strings detected"
        }));
    }

    // T1486 - Data Encrypted for Impact (ransomware indicators)
    if all_strings.contains("encrypt") || all_strings.contains("decrypt") ||
       all_strings.contains("ransom") || all_strings.contains("bitcoin") ||
       all_strings.contains(".locked") || all_strings.contains("your files") {
        techniques.push(json!({
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "confidence": 0.7,
            "evidence": "Encryption/ransom related strings detected"
        }));
    }

    // T1027 - Obfuscated Files or Information
    // Check instruction patterns
    let mut xor_count = 0;
    let mut rol_ror_count = 0;
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
        if mnemonic == "xor" { xor_count += 1; }
        if mnemonic == "rol" || mnemonic == "ror" { rol_ror_count += 1; }
    }
    if xor_count > 10 || rol_ror_count > 5 {
        techniques.push(json!({
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "confidence": 0.6,
            "evidence": format!("High XOR ({}) or ROL/ROR ({}) instruction count", xor_count, rol_ror_count)
        }));
    }

    // T1106 - Native API
    if all_strings.contains("ntdll") || all_strings.contains("zwquery") ||
       all_strings.contains("ntcreate") || all_strings.contains("ntopenprocess") {
        techniques.push(json!({
            "id": "T1106",
            "name": "Native API",
            "tactic": "Execution",
            "confidence": 0.75,
            "evidence": "Native NT API strings detected"
        }));
    }

    // T1497 - Virtualization/Sandbox Evasion
    if all_strings.contains("vmware") || all_strings.contains("virtualbox") ||
       all_strings.contains("vbox") || all_strings.contains("sandbox") ||
       all_strings.contains("wine_") {
        techniques.push(json!({
            "id": "T1497",
            "name": "Virtualization/Sandbox Evasion",
            "tactic": "Defense Evasion",
            "confidence": 0.8,
            "evidence": "VM/Sandbox detection strings found"
        }));
    }

    // For DOS programs, check for specific patterns
    if matches!(arch_mode, ArchMode::Mode16) {
        // Check for DOS-specific behaviors
        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let operands = insn.op_str().unwrap_or("");

            if mnemonic == "int" {
                if operands.contains("21") {
                    // DOS interrupt - check AH value patterns would require more context
                    // For now, just note DOS API usage
                    if !techniques.iter().any(|t| t["id"] == "T1059.006") {
                        techniques.push(json!({
                            "id": "T1059.006",
                            "name": "Command and Scripting Interpreter: DOS",
                            "tactic": "Execution",
                            "confidence": 0.9,
                            "evidence": "INT 21h DOS API calls detected"
                        }));
                    }
                }
            }
        }
    }

    techniques
}

fn detect_crypto_patterns(data: &[u8]) -> serde_json::Value {
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // AES S-box (first 16 bytes)
    let aes_sbox: [u8; 16] = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                              0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76];
    if let Some(pos) = find_pattern(data, &aes_sbox) {
        findings.push(json!({
            "type": "AES",
            "pattern": "S-box",
            "offset": format!("0x{:04X}", pos),
            "confidence": 0.95
        }));
    }

    // DES initial permutation table (partial)
    let des_ip: [u8; 8] = [58, 50, 42, 34, 26, 18, 10, 2];
    if let Some(pos) = find_pattern(data, &des_ip) {
        findings.push(json!({
            "type": "DES",
            "pattern": "Initial Permutation",
            "offset": format!("0x{:04X}", pos),
            "confidence": 0.8
        }));
    }

    // MD5 initialization constants
    let md5_init: [u8; 4] = [0x01, 0x23, 0x45, 0x67];
    if let Some(pos) = find_pattern(data, &md5_init) {
        // Check for full MD5 init sequence
        if data.len() > pos + 16 {
            let potential = &data[pos..pos+16];
            if potential[4..8] == [0x89, 0xab, 0xcd, 0xef] {
                findings.push(json!({
                    "type": "MD5",
                    "pattern": "Initialization Vector",
                    "offset": format!("0x{:04X}", pos),
                    "confidence": 0.85
                }));
            }
        }
    }

    // RC4 key scheduling (look for 256-byte ascending sequence)
    for i in 0..data.len().saturating_sub(256) {
        let mut is_sbox = true;
        for j in 0..256 {
            if data[i + j] != j as u8 {
                is_sbox = false;
                break;
            }
        }
        if is_sbox {
            findings.push(json!({
                "type": "RC4",
                "pattern": "S-box initialization",
                "offset": format!("0x{:04X}", i),
                "confidence": 0.7
            }));
            break;
        }
    }

    // Base64 alphabet
    let b64_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if let Some(pos) = find_pattern(data, b64_alpha) {
        findings.push(json!({
            "type": "Base64",
            "pattern": "Alphabet table",
            "offset": format!("0x{:04X}", pos),
            "confidence": 0.9
        }));
    }

    // CRC32 polynomial (common: 0xEDB88320)
    let crc32_poly: [u8; 4] = [0x20, 0x83, 0xB8, 0xED];
    if let Some(pos) = find_pattern(data, &crc32_poly) {
        findings.push(json!({
            "type": "CRC32",
            "pattern": "Polynomial constant",
            "offset": format!("0x{:04X}", pos),
            "confidence": 0.85
        }));
    }

    json!({
        "findings": findings,
        "count": findings.len()
    })
}

fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    data.windows(pattern.len()).position(|window| window == pattern)
}

/// Parse PE sections
fn parse_pe_sections(data: &[u8]) -> Vec<serde_json::Value> {
    let mut sections = Vec::new();

    // Check for MZ header
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return sections;
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 24 || &data[pe_offset..pe_offset+4] != b"PE\x00\x00" {
        return sections;
    }

    // COFF header
    let num_sections = u16::from_le_bytes([data[pe_offset+6], data[pe_offset+7]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[pe_offset+20], data[pe_offset+21]]) as usize;

    // Section headers start after optional header
    let section_start = pe_offset + 24 + optional_header_size;

    for i in 0..num_sections {
        let offset = section_start + i * 40;
        if offset + 40 > data.len() { break; }

        // Section name (8 bytes, null-padded)
        let name_bytes = &data[offset..offset+8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        let virtual_size = u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
        let virtual_addr = u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]);
        let raw_size = u32::from_le_bytes([data[offset+16], data[offset+17], data[offset+18], data[offset+19]]);
        let raw_ptr = u32::from_le_bytes([data[offset+20], data[offset+21], data[offset+22], data[offset+23]]);
        let characteristics = u32::from_le_bytes([data[offset+36], data[offset+37], data[offset+38], data[offset+39]]);

        // Decode characteristics
        let mut chars = Vec::new();
        if characteristics & 0x00000020 != 0 { chars.push("CODE"); }
        if characteristics & 0x00000040 != 0 { chars.push("INITIALIZED"); }
        if characteristics & 0x00000080 != 0 { chars.push("UNINITIALIZED"); }
        if characteristics & 0x20000000 != 0 { chars.push("EXECUTE"); }
        if characteristics & 0x40000000 != 0 { chars.push("READ"); }
        if characteristics & 0x80000000 != 0 { chars.push("WRITE"); }

        sections.push(json!({
            "name": name,
            "virtual_address": format!("0x{:08X}", virtual_addr),
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_pointer": format!("0x{:08X}", raw_ptr),
            "characteristics": format!("0x{:08X}", characteristics),
            "flags": chars
        }));
    }

    sections
}

/// Parse PE imports (IAT)
fn parse_pe_imports(data: &[u8]) -> Vec<serde_json::Value> {
    let mut imports = Vec::new();

    // Check for MZ header
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return imports;
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 24 || &data[pe_offset..pe_offset+4] != b"PE\x00\x00" {
        return imports;
    }

    // Check machine type to determine if 32 or 64 bit
    let machine = u16::from_le_bytes([data[pe_offset+4], data[pe_offset+5]]);
    let is_64 = machine == 0x8664;

    // Optional header starts at pe_offset + 24
    let opt_header_offset = pe_offset + 24;
    if data.len() <= opt_header_offset + 120 {
        return imports;
    }

    // Get image base and import directory RVA
    let (image_base, import_rva): (u64, u32) = if is_64 {
        // PE32+: image base at offset 24 (8 bytes)
        let base = u64::from_le_bytes([
            data[opt_header_offset+24], data[opt_header_offset+25],
            data[opt_header_offset+26], data[opt_header_offset+27],
            data[opt_header_offset+28], data[opt_header_offset+29],
            data[opt_header_offset+30], data[opt_header_offset+31],
        ]);
        // Import directory at offset 120 from optional header
        let rva = u32::from_le_bytes([
            data[opt_header_offset+120], data[opt_header_offset+121],
            data[opt_header_offset+122], data[opt_header_offset+123],
        ]);
        (base, rva)
    } else {
        // PE32: image base at offset 28 (4 bytes)
        let base = u32::from_le_bytes([
            data[opt_header_offset+28], data[opt_header_offset+29],
            data[opt_header_offset+30], data[opt_header_offset+31],
        ]) as u64;
        // Import directory at offset 104 from optional header
        let rva = u32::from_le_bytes([
            data[opt_header_offset+104], data[opt_header_offset+105],
            data[opt_header_offset+106], data[opt_header_offset+107],
        ]);
        (base, rva)
    };

    if import_rva == 0 {
        return imports;
    }

    // Need to convert RVA to file offset using section table
    let sections = parse_pe_sections(data);
    let import_offset = rva_to_offset(import_rva, &sections, data);
    if import_offset == 0 {
        return imports;
    }

    // Parse Import Directory Table
    let mut idx = 0;
    loop {
        let entry_offset = import_offset + idx * 20;
        if entry_offset + 20 > data.len() { break; }

        let lookup_rva = u32::from_le_bytes([
            data[entry_offset], data[entry_offset+1],
            data[entry_offset+2], data[entry_offset+3],
        ]);
        let name_rva = u32::from_le_bytes([
            data[entry_offset+12], data[entry_offset+13],
            data[entry_offset+14], data[entry_offset+15],
        ]);
        let iat_rva = u32::from_le_bytes([
            data[entry_offset+16], data[entry_offset+17],
            data[entry_offset+18], data[entry_offset+19],
        ]);

        // End of import directory
        if lookup_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        // Get DLL name
        let name_offset = rva_to_offset(name_rva, &sections, data);
        let dll_name = if name_offset > 0 {
            read_string(data, name_offset)
        } else {
            "???".to_string()
        };

        // Parse functions from lookup table (or IAT if lookup is 0)
        let thunk_rva = if lookup_rva != 0 { lookup_rva } else { iat_rva };
        let thunk_offset = rva_to_offset(thunk_rva, &sections, data);

        let mut functions: Vec<serde_json::Value> = Vec::new();
        if thunk_offset > 0 {
            let mut func_idx = 0;
            loop {
                let func_entry = thunk_offset + func_idx * (if is_64 { 8 } else { 4 });
                if func_entry + 4 > data.len() { break; }

                let thunk_data: u64 = if is_64 {
                    if func_entry + 8 > data.len() { break; }
                    u64::from_le_bytes([
                        data[func_entry], data[func_entry+1],
                        data[func_entry+2], data[func_entry+3],
                        data[func_entry+4], data[func_entry+5],
                        data[func_entry+6], data[func_entry+7],
                    ])
                } else {
                    u32::from_le_bytes([
                        data[func_entry], data[func_entry+1],
                        data[func_entry+2], data[func_entry+3],
                    ]) as u64
                };

                if thunk_data == 0 { break; }

                // Check if import by ordinal
                let ordinal_flag = if is_64 { 0x8000000000000000u64 } else { 0x80000000u64 };
                if thunk_data & ordinal_flag != 0 {
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    functions.push(json!({
                        "name": format!("Ordinal_{}", ordinal),
                        "ordinal": ordinal,
                        "hint": null,
                        "iat_address": format!("0x{:08X}", image_base + iat_rva as u64 + func_idx as u64 * (if is_64 { 8 } else { 4 }))
                    }));
                } else {
                    // Import by name
                    let hint_name_rva = (thunk_data & 0x7FFFFFFF) as u32;
                    let hint_name_offset = rva_to_offset(hint_name_rva, &sections, data);
                    if hint_name_offset > 0 && hint_name_offset + 2 < data.len() {
                        let hint = u16::from_le_bytes([data[hint_name_offset], data[hint_name_offset+1]]);
                        let func_name = read_string(data, hint_name_offset + 2);
                        functions.push(json!({
                            "name": func_name,
                            "ordinal": null,
                            "hint": hint,
                            "iat_address": format!("0x{:08X}", image_base + iat_rva as u64 + func_idx as u64 * (if is_64 { 8 } else { 4 }))
                        }));
                    }
                }

                func_idx += 1;
                if func_idx > 500 { break; } // Safety limit
            }
        }

        imports.push(json!({
            "dll": dll_name,
            "function_count": functions.len(),
            "iat_rva": format!("0x{:08X}", iat_rva),
            "functions": functions
        }));

        idx += 1;
        if idx > 100 { break; } // Safety limit
    }

    imports
}

/// Parse PE exports (EAT)
fn parse_pe_exports(data: &[u8]) -> serde_json::Value {
    // Check for MZ header
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return json!({ "dll_name": null, "functions": [], "count": 0 });
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 24 || &data[pe_offset..pe_offset+4] != b"PE\x00\x00" {
        return json!({ "dll_name": null, "functions": [], "count": 0 });
    }

    let machine = u16::from_le_bytes([data[pe_offset+4], data[pe_offset+5]]);
    let is_64 = machine == 0x8664;

    let opt_header_offset = pe_offset + 24;

    // Get export directory RVA
    let export_rva: u32 = if is_64 {
        if data.len() <= opt_header_offset + 112 { return json!({ "dll_name": null, "functions": [], "count": 0 }); }
        u32::from_le_bytes([
            data[opt_header_offset+112], data[opt_header_offset+113],
            data[opt_header_offset+114], data[opt_header_offset+115],
        ])
    } else {
        if data.len() <= opt_header_offset + 96 { return json!({ "dll_name": null, "functions": [], "count": 0 }); }
        u32::from_le_bytes([
            data[opt_header_offset+96], data[opt_header_offset+97],
            data[opt_header_offset+98], data[opt_header_offset+99],
        ])
    };

    if export_rva == 0 {
        return json!({ "dll_name": null, "functions": [], "count": 0 });
    }

    let sections = parse_pe_sections(data);
    let export_offset = rva_to_offset(export_rva, &sections, data);
    if export_offset == 0 || export_offset + 40 > data.len() {
        return json!({ "dll_name": null, "functions": [], "count": 0 });
    }

    // Parse Export Directory Table
    let name_rva = u32::from_le_bytes([data[export_offset+12], data[export_offset+13], data[export_offset+14], data[export_offset+15]]);
    let ordinal_base = u32::from_le_bytes([data[export_offset+16], data[export_offset+17], data[export_offset+18], data[export_offset+19]]);
    let num_functions = u32::from_le_bytes([data[export_offset+20], data[export_offset+21], data[export_offset+22], data[export_offset+23]]);
    let num_names = u32::from_le_bytes([data[export_offset+24], data[export_offset+25], data[export_offset+26], data[export_offset+27]]);
    let addr_table_rva = u32::from_le_bytes([data[export_offset+28], data[export_offset+29], data[export_offset+30], data[export_offset+31]]);
    let name_ptr_rva = u32::from_le_bytes([data[export_offset+32], data[export_offset+33], data[export_offset+34], data[export_offset+35]]);
    let ordinal_table_rva = u32::from_le_bytes([data[export_offset+36], data[export_offset+37], data[export_offset+38], data[export_offset+39]]);

    let dll_name_offset = rva_to_offset(name_rva, &sections, data);
    let dll_name = if dll_name_offset > 0 { read_string(data, dll_name_offset) } else { "???".to_string() };

    let addr_offset = rva_to_offset(addr_table_rva, &sections, data);
    let name_ptr_offset = rva_to_offset(name_ptr_rva, &sections, data);
    let ordinal_offset = rva_to_offset(ordinal_table_rva, &sections, data);

    let mut functions: Vec<serde_json::Value> = Vec::new();

    // Build name -> ordinal mapping
    let mut name_map: std::collections::HashMap<u16, String> = std::collections::HashMap::new();
    if name_ptr_offset > 0 && ordinal_offset > 0 {
        for i in 0..num_names as usize {
            let name_ptr_entry = name_ptr_offset + i * 4;
            let ord_entry = ordinal_offset + i * 2;
            if name_ptr_entry + 4 > data.len() || ord_entry + 2 > data.len() { break; }

            let fn_name_rva = u32::from_le_bytes([
                data[name_ptr_entry], data[name_ptr_entry+1],
                data[name_ptr_entry+2], data[name_ptr_entry+3],
            ]);
            let ordinal_idx = u16::from_le_bytes([data[ord_entry], data[ord_entry+1]]);

            let fn_name_offset = rva_to_offset(fn_name_rva, &sections, data);
            if fn_name_offset > 0 {
                let fn_name = read_string(data, fn_name_offset);
                name_map.insert(ordinal_idx, fn_name);
            }
        }
    }

    // Parse all exports
    if addr_offset > 0 {
        for i in 0..num_functions as usize {
            let addr_entry = addr_offset + i * 4;
            if addr_entry + 4 > data.len() { break; }

            let rva = u32::from_le_bytes([
                data[addr_entry], data[addr_entry+1],
                data[addr_entry+2], data[addr_entry+3],
            ]);

            if rva == 0 { continue; }

            let ordinal = ordinal_base + i as u32;
            let name = name_map.get(&(i as u16)).cloned();

            functions.push(json!({
                "ordinal": ordinal,
                "name": name,
                "rva": format!("0x{:08X}", rva)
            }));
        }
    }

    json!({
        "dll_name": dll_name,
        "functions": functions,
        "count": functions.len()
    })
}

/// Convert RVA to file offset using section information
fn rva_to_offset(rva: u32, sections: &[serde_json::Value], data: &[u8]) -> usize {
    for section in sections {
        let va_str = section["virtual_address"].as_str().unwrap_or("0x0");
        let va = u32::from_str_radix(&va_str[2..], 16).unwrap_or(0);
        let vsize = section["virtual_size"].as_u64().unwrap_or(0) as u32;
        let raw_str = section["raw_pointer"].as_str().unwrap_or("0x0");
        let raw_ptr = u32::from_str_radix(&raw_str[2..], 16).unwrap_or(0);

        if rva >= va && rva < va + vsize {
            let offset = (rva - va + raw_ptr) as usize;
            if offset < data.len() {
                return offset;
            }
        }
    }
    0
}

/// Read null-terminated string from data
fn read_string(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
        if end - offset > 256 { break; } // Safety limit
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

fn get_initial_registers(arch_mode: ArchMode, base_address: u64) -> serde_json::Value {
    match arch_mode {
        ArchMode::Mode16 => {
            // DOS COM file initial state
            json!({
                "mode": "16-bit",
                "AX": "0000",
                "BX": "0000",
                "CX": "00FF",
                "DX": "0000",
                "SI": "0100",
                "DI": "FFFE",
                "BP": "0000",
                "SP": "FFFE",
                "IP": format!("{:04X}", base_address),
                "CS": "PSP",
                "DS": "PSP",
                "SS": "PSP",
                "ES": "PSP",
                "FLAGS": "0202",
                "flags_decoded": {
                    "CF": 0, "PF": 0, "AF": 0, "ZF": 0,
                    "SF": 0, "TF": 0, "IF": 1, "DF": 0, "OF": 0
                }
            })
        },
        ArchMode::Mode32 => {
            // Win32 PE initial state (approximation)
            json!({
                "mode": "32-bit",
                "EAX": "00000000",
                "EBX": "00000000",
                "ECX": "00000000",
                "EDX": "00000000",
                "ESI": "00000000",
                "EDI": "00000000",
                "EBP": "00000000",
                "ESP": "0012FF00",
                "EIP": format!("{:08X}", base_address),
                "CS": "001B",
                "DS": "0023",
                "SS": "0023",
                "ES": "0023",
                "FS": "003B",
                "GS": "0000",
                "EFLAGS": "00000202",
                "flags_decoded": {
                    "CF": 0, "PF": 0, "AF": 0, "ZF": 0,
                    "SF": 0, "TF": 0, "IF": 1, "DF": 0, "OF": 0
                }
            })
        },
        ArchMode::Mode64 => {
            // Win64 PE initial state (approximation)
            json!({
                "mode": "64-bit",
                "RAX": "0000000000000000",
                "RBX": "0000000000000000",
                "RCX": "0000000000000000",
                "RDX": "0000000000000000",
                "RSI": "0000000000000000",
                "RDI": "0000000000000000",
                "RBP": "0000000000000000",
                "RSP": "000000000012F000",
                "R8":  "0000000000000000",
                "R9":  "0000000000000000",
                "R10": "0000000000000000",
                "R11": "0000000000000000",
                "R12": "0000000000000000",
                "R13": "0000000000000000",
                "R14": "0000000000000000",
                "R15": "0000000000000000",
                "RIP": format!("{:016X}", base_address),
                "CS": "0033",
                "DS": "002B",
                "SS": "002B",
                "ES": "002B",
                "FS": "0053",
                "GS": "002B",
                "RFLAGS": "0000000000000202",
                "flags_decoded": {
                    "CF": 0, "PF": 0, "AF": 0, "ZF": 0,
                    "SF": 0, "TF": 0, "IF": 1, "DF": 0, "OF": 0
                }
            })
        }
    }
}

// ============================================================================
// Tauri Commands - Claude AI
// ============================================================================

use std::sync::OnceLock;

/// Runtime API key cache (loaded from disk or set via UI)
static RUNTIME_API_KEY: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn get_runtime_key_store() -> &'static Mutex<Option<String>> {
    RUNTIME_API_KEY.get_or_init(|| {
        // Try to load from disk on first access
        Mutex::new(load_api_key_from_disk())
    })
}

/// Get the config file path for storing the API key
fn get_api_key_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|p| p.join("analyzebugger").join("api_key"))
}

/// Load API key from disk
fn load_api_key_from_disk() -> Option<String> {
    let path = get_api_key_path()?;
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|k| !k.is_empty() && k.starts_with("sk-ant-api"))
}

/// Save API key to disk
fn save_api_key_to_disk(key: &str) -> Result<(), String> {
    let path = get_api_key_path().ok_or("Could not determine config directory")?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    std::fs::write(&path, key)
        .map_err(|e| format!("Failed to save API key: {}", e))?;

    eprintln!("[API Key] Saved to {:?}", path);
    Ok(())
}

/// Get API key - checks runtime cache, disk, then environment variable
fn get_api_key() -> Option<String> {
    // First check runtime cache
    if let Ok(guard) = get_runtime_key_store().lock() {
        if let Some(ref key) = *guard {
            if !key.is_empty() {
                return Some(key.clone());
            }
        }
    }
    // Fall back to environment variable
    std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty())
}

/// Check if API key is configured
#[tauri::command]
fn has_api_key() -> bool {
    get_api_key().is_some()
}

/// Set API key (stores in memory AND persists to disk)
#[tauri::command]
fn set_api_key(key: String) -> Result<bool, String> {
    if key.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    if !key.starts_with("sk-ant-api") {
        return Err("Invalid API key format. Key should start with 'sk-ant-api'".to_string());
    }

    // Save to disk for persistence
    save_api_key_to_disk(&key)?;

    // Update runtime cache
    let store = get_runtime_key_store();
    let mut guard = store.lock().map_err(|e| e.to_string())?;
    *guard = Some(key);
    Ok(true)
}



#[tauri::command]
async fn ask_claude(prompt: String, context: String) -> Result<String, String> {
    eprintln!("[ask_claude] Called with prompt length: {}", prompt.len());

    // Get API key from environment (OAuth not supported by Anthropic API)
    let api_key = match get_api_key() {
        Some(key) => key,
        None => {
            return Ok("**API Key Required**

The Anthropic API requires an API key.

To enable AI analysis:
1. Get an API key from https://console.anthropic.com/
2. Set the environment variable:
   PowerShell: $env:ANTHROPIC_API_KEY = 'sk-ant-api...'
3. Restart AnalyzeBugger".to_string());
        }
    };

    let client = reqwest::Client::new();

    let body = json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "messages": [
            {
                "role": "user",
                "content": format!(
                    "You are an expert reverse engineer analyzing a binary. Here is the current debugging context:

{}

User question: {}",
                    context,
                    prompt
                )
            }
        ]
    });

    // Make API request with API key
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    let status = response.status();
    let response_json: serde_json::Value = response.json().await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    // Check for API errors
    if !status.is_success() {
        if let Some(error) = response_json["error"]["message"].as_str() {
            return Err(format!("Claude API error: {}", error));
        }
        return Err(format!("Claude API returned status {}", status));
    }

    if let Some(content) = response_json["content"].as_array() {
        if let Some(text) = content.first().and_then(|c| c["text"].as_str()) {
            return Ok(text.to_string());
        }
    }

    Err("Failed to parse Claude response".to_string())
}

// ================================================================================
// Tauri Commands - Intel PT
// ============================================================================

#[tauri::command]
fn get_intel_pt_status(state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    Ok(manager.get_status().to_string())
}

#[tauri::command]
fn start_pt_process_trace(process_id: u32, preset: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;

    let config = match preset.as_str() {
        "high_fidelity" => intel_pt::PtTraceConfig::high_fidelity(),
        "low_overhead" => intel_pt::PtTraceConfig::low_overhead(),
        "timing_analysis" => intel_pt::PtTraceConfig::timing_analysis(),
        "control_flow" => intel_pt::PtTraceConfig::control_flow_analysis(),
        "anti_debug" => intel_pt::PtTraceConfig::anti_debug_detection(),
        "code_coverage" => intel_pt::PtTraceConfig::code_coverage(),
        _ => intel_pt::PtTraceConfig::default(),
    };

    let trace_id = manager.start_process_trace(process_id, config)?;
    Ok(json!({"trace_id": trace_id, "status": "started"}).to_string())
}

#[tauri::command]
fn stop_pt_trace(trace_id: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    manager.stop_trace(&trace_id)?;
    Ok(json!({"trace_id": trace_id, "status": "stopped"}).to_string())
}

#[tauri::command]
fn get_pt_trace_data(trace_id: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    let data = manager.get_trace_data(&trace_id)?;

    Ok(json!({
        "trace_id": data.trace_id,
        "process_id": data.process_id,
        "buffer_size": data.buffer_size,
        "packet_count_estimate": data.packet_count_estimate,
        "overflow": data.overflow,
        "start_tsc": data.start_tsc,
        "end_tsc": data.end_tsc
    }).to_string())
}

#[tauri::command]
fn decode_pt_trace(trace_id: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    let decoded = manager.decode_trace(&trace_id)?;

    // Return summary (full data would be too large)
    Ok(json!({
        "trace_id": decoded.trace_id,
        "total_packets": decoded.stats.total_packets,
        "total_branches": decoded.stats.total_branches,
        "taken_branches": decoded.stats.taken_branches,
        "not_taken_branches": decoded.stats.not_taken_branches,
        "calls": decoded.stats.calls,
        "returns": decoded.stats.returns,
        "call_return_balance": decoded.stats.call_return_balance,
        "packets_by_type": decoded.stats.packets_by_type,
        "mode_changes": decoded.mode_changes.len(),
        "cr3_changes": decoded.cr3_changes.len(),
        "overflows": decoded.overflow_positions.len(),
        "errors": decoded.errors.len()
    }).to_string())
}

#[tauri::command]
fn analyze_pt_timing(trace_id: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    let analysis = manager.analyze_timing(&trace_id)?;

    Ok(json!({
        "stats": {
            "total_duration_ns": analysis.stats.total_duration_ns,
            "avg_cycles_per_branch": analysis.stats.avg_cycles_per_branch,
            "median_cycles_per_branch": analysis.stats.median_cycles_per_branch,
            "min_cycles": analysis.stats.min_cycles,
            "max_cycles": analysis.stats.max_cycles,
            "std_deviation": analysis.stats.std_deviation,
            "tsc_frequency_hz": analysis.stats.tsc_frequency_hz
        },
        "anomalies": analysis.anomalies.iter().map(|a| json!({
            "type": format!("{:?}", a.anomaly_type),
            "address": format!("0x{:x}", a.address),
            "expected": a.expected_cycles,
            "observed": a.observed_cycles,
            "deviation": a.deviation_factor,
            "severity": a.severity,
            "description": a.description
        })).collect::<Vec<_>>(),
        "slow_regions": analysis.slow_regions.iter().take(10).map(|r| json!({
            "start": format!("0x{:x}", r.start_address),
            "end": format!("0x{:x}", r.end_address),
            "total_cycles": r.total_cycles,
            "exec_count": r.exec_count,
            "avg_cycles": r.avg_cycles,
            "cause": r.possible_cause
        })).collect::<Vec<_>>(),
        "fast_regions": analysis.fast_regions.iter().take(10).map(|r| json!({
            "start": format!("0x{:x}", r.start_address),
            "avg_cycles": r.avg_cycles,
            "reason": r.likely_reason
        })).collect::<Vec<_>>()
    }).to_string())
}

#[tauri::command]
fn get_pt_cfg(trace_id: String, state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    let cfg = manager.reconstruct_cfg(&trace_id)?;

    Ok(json!({
        "blocks": cfg.blocks.iter().map(|b| json!({
            "id": b.id,
            "start": format!("0x{:x}", b.start_address),
            "end": format!("0x{:x}", b.end_address),
            "exec_count": b.exec_count,
            "exit_type": format!("{:?}", b.exit_type)
        })).collect::<Vec<_>>(),
        "edges": cfg.edges.iter().map(|e| json!({
            "from": e.from_block,
            "to": e.to_block,
            "type": format!("{:?}", e.edge_type),
            "count": e.exec_count
        })).collect::<Vec<_>>(),
        "functions": cfg.functions.iter().take(50).map(|f| json!({
            "entry": format!("0x{:x}", f.entry_address),
            "call_count": f.call_count,
            "callers": f.callers.len()
        })).collect::<Vec<_>>(),
        "entry_points": cfg.entry_points.iter().map(|e| format!("0x{:x}", e)).collect::<Vec<_>>(),
        "call_sites": cfg.call_sites.len()
    }).to_string())
}

#[tauri::command]
fn list_pt_sessions(state: State<AppState>) -> Result<String, String> {
    let manager = state.intel_pt_manager.lock().map_err(|e| e.to_string())?;
    let sessions = manager.list_sessions()?;

    Ok(json!({
        "sessions": sessions.iter().map(|s| json!({
            "id": s.id,
            "state": format!("{:?}", s.state),
            "process_id": s.process_id,
            "core_id": s.core_id,
            "buffer_size": s.buffer_size,
            "overflow": s.overflow
        })).collect::<Vec<_>>()
    }).to_string())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_hex_address(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

// ============================================================================
// Tauri App Setup
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize session manager with DLL
    let mut session_manager = SessionManager::new();

    // Load DLL
    let dll_path = std::path::Path::new(r"C:\Claude\tools\bip\bin\DebugEngine.dll");
    if let Err(e) = session_manager.load_dll(dll_path) {
        eprintln!("Warning: Failed to load DebugEngine.dll: {}", e);
    }

    // Initialize Intel PT manager
    let intel_pt_manager = IntelPTManager::new();
    if intel_pt_manager.is_available() {
        eprintln!("Intel PT: Available with capabilities: {:?}", intel_pt_manager.get_capabilities());
    } else {
        eprintln!("Intel PT: Not available on this system");
    }

    // Initialize MCP API state
    // Project root is the AnalyzeBugger source directory for self-modification
    let project_root = std::env::var("ANALYZEBUGGER_PROJECT_ROOT")
        .unwrap_or_else(|_| "C:/Claude/tools/bip/analyzebugger".to_string());
    let mcp_state = Arc::new(mcp_api::McpApiState::new(project_root));

    // Start MCP API server in background
    let mcp_state_clone = mcp_state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime for MCP API");
        rt.block_on(async {
            if let Err(e) = mcp_api::start_server((*mcp_state_clone).clone()).await {
                eprintln!("[MCP API] Server error: {}", e);
            }
        });
    });

    let app_state = AppState {
        session_manager: Mutex::new(session_manager),
        intel_pt_manager: Mutex::new(intel_pt_manager),
        mcp_state,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            // Debug session commands
            get_status,
            launch_target,
            stop_session,
            continue_execution,
            pause_execution,
            step_into,
            step_over,
            get_registers,
            read_memory,
            get_modules,
            disassemble,
            set_breakpoint,
            remove_breakpoint,
            ask_claude,
            has_api_key,
            set_api_key,
            analyze_file,
            // Intel PT commands
            get_intel_pt_status,
            start_pt_process_trace,
            stop_pt_trace,
            get_pt_trace_data,
            decode_pt_trace,
            analyze_pt_timing,
            get_pt_cfg,
            list_pt_sessions,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
