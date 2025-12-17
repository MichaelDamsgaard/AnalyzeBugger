//! Intel PT Packet Decoder
//!
//! Decodes raw Intel PT trace data into structured packets.
//! Based on Intel PT packet format specification.

use super::types::*;

/// Intel PT Packet Decoder
pub struct PtDecoder {
    position: usize,
    last_ip: u64,
    exec_mode: ExecMode,
    current_tsc: u64,
    cycle_count: u64,
    errors: Vec<String>,
}

impl PtDecoder {
    pub fn new() -> Self {
        Self {
            position: 0,
            last_ip: 0,
            exec_mode: ExecMode::Mode64,
            current_tsc: 0,
            cycle_count: 0,
            errors: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.position = 0;
        self.last_ip = 0;
        self.exec_mode = ExecMode::Mode64;
        self.current_tsc = 0;
        self.cycle_count = 0;
        self.errors.clear();
    }

    pub fn decode_all(&mut self, data: &[u8]) -> Vec<PtPacket> {
        self.reset();
        let mut packets = Vec::new();

        while self.position < data.len() {
            match self.decode_packet(data) {
                Ok(Some(packet)) => packets.push(packet),
                Ok(None) => self.position += 1,
                Err(e) => {
                    self.errors.push(format!("Decode error at {}: {}", self.position, e));
                    if !self.try_resync(data) { break; }
                }
            }
        }
        packets
    }

    fn decode_packet(&mut self, data: &[u8]) -> Result<Option<PtPacket>, String> {
        if self.position >= data.len() {
            return Err("End of data".to_string());
        }

        let offset = self.position as u64;
        let byte0 = data[self.position];

        // PSB check
        if self.check_psb(data) {
            return self.decode_psb(data, offset);
        }

        match byte0 {
            0x00 => {
                self.position += 1;
                Ok(Some(PtPacket {
                    packet_type: PtPacketType::Pad,
                    raw_bytes: vec![0x00],
                    offset,
                    payload: PtPacketPayload::None,
                }))
            }
            b if (b & 0x01) == 0 && b != 0x00 => self.decode_short_tnt(data, offset),
            0x02 => self.decode_extended_packet(data, offset),
            0x0D => self.decode_tip(data, offset, PtPacketType::Tip),
            0x11 => self.decode_tip(data, offset, PtPacketType::TipPge),
            0x01 => self.decode_tip(data, offset, PtPacketType::TipPgd),
            0x1D => self.decode_fup(data, offset),
            0x99 => self.decode_mode(data, offset),
            0x19 => self.decode_tsc(data, offset),
            0x59 => self.decode_mtc(data, offset),
            b if (b & 0x03) == 0x03 => self.decode_cyc(data, offset),
            _ => {
                self.position += 1;
                Ok(Some(PtPacket {
                    packet_type: PtPacketType::Unknown,
                    raw_bytes: vec![byte0],
                    offset,
                    payload: PtPacketPayload::Raw(vec![byte0]),
                }))
            }
        }
    }

    fn check_psb(&self, data: &[u8]) -> bool {
        if self.position + 16 > data.len() { return false; }
        let psb: [u8; 16] = [0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                             0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82];
        data[self.position..self.position + 16] == psb
    }

    fn decode_psb(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        let raw_bytes = data[self.position..self.position + 16].to_vec();
        self.position += 16;
        self.last_ip = 0;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Psb,
            raw_bytes,
            offset,
            payload: PtPacketPayload::None,
        }))
    }

    fn decode_short_tnt(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        let byte0 = data[self.position];
        self.position += 1;
        let mut bits = (byte0 >> 1) as u64;
        let count = if bits != 0 {
            let stop_pos = 63 - bits.leading_zeros() as u8;
            bits &= (1u64 << stop_pos) - 1;
            stop_pos
        } else { 0 };
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Tnt,
            raw_bytes: vec![byte0],
            offset,
            payload: PtPacketPayload::Tnt { bits, count },
        }))
    }

    fn decode_extended_packet(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 1 >= data.len() {
            return Err("Truncated extended packet".to_string());
        }
        let byte1 = data[self.position + 1];
        match byte1 {
            0x23 => {
                let raw_bytes = data[self.position..self.position + 2].to_vec();
                self.position += 2;
                Ok(Some(PtPacket {
                    packet_type: PtPacketType::Psbend,
                    raw_bytes,
                    offset,
                    payload: PtPacketPayload::None,
                }))
            }
            0xA3 => self.decode_long_tnt(data, offset),
            0x43 => self.decode_pip(data, offset),
            0xF3 => {
                let raw_bytes = data[self.position..self.position + 2].to_vec();
                self.position += 2;
                Ok(Some(PtPacket {
                    packet_type: PtPacketType::Ovf,
                    raw_bytes,
                    offset,
                    payload: PtPacketPayload::None,
                }))
            }
            0x03 => self.decode_cbr(data, offset),
            _ => {
                let raw_bytes = data[self.position..self.position + 2].to_vec();
                self.position += 2;
                Ok(Some(PtPacket {
                    packet_type: PtPacketType::Unknown,
                    raw_bytes: raw_bytes.clone(),
                    offset,
                    payload: PtPacketPayload::Raw(raw_bytes),
                }))
            }
        }
    }

    fn decode_long_tnt(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 8 > data.len() {
            return Err("Truncated long TNT".to_string());
        }
        let raw_bytes = data[self.position..self.position + 8].to_vec();
        self.position += 8;
        let mut bits = 0u64;
        for i in 0..6 { bits |= (raw_bytes[2 + i] as u64) << (i * 8); }
        let count = if bits != 0 {
            let stop_pos = 63 - bits.leading_zeros() as u8;
            bits &= (1u64 << stop_pos) - 1;
            stop_pos
        } else { 0 };
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Tnt,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Tnt { bits, count },
        }))
    }

    fn decode_tip(&mut self, data: &[u8], offset: u64, tip_type: PtPacketType) -> Result<Option<PtPacket>, String> {
        let byte0 = data[self.position];
        let ip_bytes = (byte0 >> 5) & 0x07;
        let (ip, compression, packet_len) = self.decode_ip_payload(data, ip_bytes)?;
        let raw_bytes = data[self.position..self.position + packet_len].to_vec();
        self.position += packet_len;
        if compression != IpCompression::Full || ip != 0 { self.last_ip = ip; }
        Ok(Some(PtPacket {
            packet_type: tip_type,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Tip { ip, compression },
        }))
    }

    fn decode_fup(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        let byte0 = data[self.position];
        let ip_bytes = (byte0 >> 5) & 0x07;
        let (ip, compression, packet_len) = self.decode_ip_payload(data, ip_bytes)?;
        let raw_bytes = data[self.position..self.position + packet_len].to_vec();
        self.position += packet_len;
        if compression != IpCompression::Full || ip != 0 { self.last_ip = ip; }
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Fup,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Fup { ip, compression },
        }))
    }

    fn decode_ip_payload(&self, data: &[u8], ip_bytes: u8) -> Result<(u64, IpCompression, usize), String> {
        let (compression, extra_bytes) = match ip_bytes {
            0 => (IpCompression::Full, 0),
            1 => (IpCompression::Lower16, 2),
            2 => (IpCompression::Lower32, 4),
            3 => (IpCompression::SignExt48, 6),
            4 => (IpCompression::Upper32Suppressed, 6),
            6 => (IpCompression::Full, 8),
            _ => return Err(format!("Invalid IP compression: {}", ip_bytes)),
        };
        if self.position + 1 + extra_bytes > data.len() {
            return Err("Truncated IP packet".to_string());
        }
        let mut ip = self.last_ip;
        match compression {
            IpCompression::Full if extra_bytes == 0 => ip = 0,
            IpCompression::Lower16 => {
                let low16 = u16::from_le_bytes([data[self.position + 1], data[self.position + 2]]) as u64;
                ip = (ip & !0xFFFF) | low16;
            }
            IpCompression::Lower32 => {
                let low32 = u32::from_le_bytes([
                    data[self.position + 1], data[self.position + 2],
                    data[self.position + 3], data[self.position + 4],
                ]) as u64;
                ip = (ip & !0xFFFFFFFF) | low32;
            }
            IpCompression::SignExt48 | IpCompression::Upper32Suppressed => {
                let low48 = u64::from_le_bytes([
                    data[self.position + 1], data[self.position + 2],
                    data[self.position + 3], data[self.position + 4],
                    data[self.position + 5], data[self.position + 6], 0, 0,
                ]);
                ip = if low48 & (1u64 << 47) != 0 {
                    low48 | 0xFFFF_0000_0000_0000
                } else { low48 };
            }
            IpCompression::Full => {
                ip = u64::from_le_bytes([
                    data[self.position + 1], data[self.position + 2],
                    data[self.position + 3], data[self.position + 4],
                    data[self.position + 5], data[self.position + 6],
                    data[self.position + 7], data[self.position + 8],
                ]);
            }
            _ => {}
        }
        Ok((ip, compression, 1 + extra_bytes))
    }

    fn decode_mode(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 2 > data.len() { return Err("Truncated MODE".to_string()); }
        let raw_bytes = data[self.position..self.position + 2].to_vec();
        let byte1 = data[self.position + 1];
        self.position += 2;
        let leaf = byte1 >> 5;
        let exec_mode = match byte1 & 0x03 {
            0 => ExecMode::Mode16,
            1 => ExecMode::Mode64,
            _ => ExecMode::Mode32,
        };
        self.exec_mode = exec_mode;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Mode,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Mode { exec_mode, leaf },
        }))
    }

    fn decode_tsc(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 8 > data.len() { return Err("Truncated TSC".to_string()); }
        let raw_bytes = data[self.position..self.position + 8].to_vec();
        self.position += 8;
        let tsc = u64::from_le_bytes([
            raw_bytes[1], raw_bytes[2], raw_bytes[3], raw_bytes[4],
            raw_bytes[5], raw_bytes[6], raw_bytes[7], 0,
        ]);
        self.current_tsc = tsc;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Tsc,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Tsc { tsc },
        }))
    }

    fn decode_mtc(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 2 > data.len() { return Err("Truncated MTC".to_string()); }
        let raw_bytes = data[self.position..self.position + 2].to_vec();
        let ctc = data[self.position + 1];
        self.position += 2;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Mtc,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Mtc { ctc },
        }))
    }

    fn decode_cyc(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        let mut cycles = 0u64;
        let mut shift = 0;
        let start_pos = self.position;
        loop {
            if self.position >= data.len() { return Err("Truncated CYC".to_string()); }
            let byte = data[self.position];
            self.position += 1;
            if self.position == start_pos + 1 {
                cycles = ((byte >> 2) & 0x1F) as u64;
                shift = 5;
                if (byte & 0x01) == 0 { break; }
            } else {
                cycles |= ((byte & 0x7F) as u64) << shift;
                shift += 7;
                if (byte & 0x80) == 0 { break; }
            }
            if self.position - start_pos > 10 { return Err("CYC too long".to_string()); }
        }
        let raw_bytes = data[start_pos..self.position].to_vec();
        self.cycle_count += cycles;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Cyc,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Cyc { cycles },
        }))
    }

    fn decode_pip(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 8 > data.len() { return Err("Truncated PIP".to_string()); }
        let raw_bytes = data[self.position..self.position + 8].to_vec();
        self.position += 8;
        let cr3_payload = u64::from_le_bytes([
            raw_bytes[2], raw_bytes[3], raw_bytes[4], raw_bytes[5],
            raw_bytes[6], raw_bytes[7], 0, 0,
        ]);
        let nr = (raw_bytes[2] & 0x01) != 0;
        let cr3 = (cr3_payload >> 1) << 5;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Pip,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Pip { cr3, nr },
        }))
    }

    fn decode_cbr(&mut self, data: &[u8], offset: u64) -> Result<Option<PtPacket>, String> {
        if self.position + 4 > data.len() { return Err("Truncated CBR".to_string()); }
        let raw_bytes = data[self.position..self.position + 4].to_vec();
        let ratio = data[self.position + 2];
        self.position += 4;
        Ok(Some(PtPacket {
            packet_type: PtPacketType::Cbr,
            raw_bytes,
            offset,
            payload: PtPacketPayload::Cbr { ratio },
        }))
    }

    fn try_resync(&mut self, data: &[u8]) -> bool {
        while self.position + 16 <= data.len() {
            if self.check_psb(data) { return true; }
            self.position += 1;
        }
        false
    }

    pub fn get_errors(&self) -> &[String] { &self.errors }
    pub fn get_exec_mode(&self) -> ExecMode { self.exec_mode }
}

impl Default for PtDecoder {
    fn default() -> Self { Self::new() }
}

/// Decode raw trace data into a DecodedTrace
pub fn decode_trace(raw_data: &[u8]) -> Result<DecodedTrace, String> {
    let mut decoder = PtDecoder::new();
    let packets = decoder.decode_all(raw_data);

    let mut branches = Vec::new();
    let mut timing_events = Vec::new();
    let mut mode_changes = Vec::new();
    let mut cr3_changes = Vec::new();
    let vmcs_changes = Vec::new();
    let mut ptwrites = Vec::new();
    let mut overflow_positions = Vec::new();

    let mut current_ip = 0u64;
    let mut current_tsc = 0u64;
    let mut current_cycles = 0u64;

    for packet in &packets {
        match &packet.payload {
            PtPacketPayload::Tip { ip, .. } | PtPacketPayload::Fup { ip, .. } => {
                if *ip != 0 && current_ip != 0 {
                    branches.push(BranchEvent {
                        source: current_ip,
                        target: *ip,
                        taken: true,
                        branch_type: BranchType::Unknown,
                        timing: Some(TimingEvent {
                            offset: packet.offset,
                            tsc: Some(current_tsc),
                            mtc: None,
                            cycles: Some(current_cycles),
                            timestamp_ns: 0,
                        }),
                        exec_mode: decoder.get_exec_mode(),
                    });
                }
                current_ip = *ip;
            }
            PtPacketPayload::Tnt { bits, count } => {
                for i in 0..*count {
                    branches.push(BranchEvent {
                        source: current_ip,
                        target: 0,
                        taken: (bits >> i) & 1 == 1,
                        branch_type: BranchType::Conditional,
                        timing: None,
                        exec_mode: decoder.get_exec_mode(),
                    });
                }
            }
            PtPacketPayload::Tsc { tsc } => {
                current_tsc = *tsc;
                timing_events.push(TimingEvent {
                    offset: packet.offset,
                    tsc: Some(*tsc),
                    mtc: None,
                    cycles: Some(current_cycles),
                    timestamp_ns: 0,
                });
            }
            PtPacketPayload::Cyc { cycles } => current_cycles += cycles,
            PtPacketPayload::Mode { exec_mode, .. } => mode_changes.push((packet.offset, *exec_mode)),
            PtPacketPayload::Pip { cr3, .. } => cr3_changes.push((packet.offset, *cr3)),
            PtPacketPayload::Ptw { payload, .. } => ptwrites.push((packet.offset, *payload)),
            _ => {}
        }
        if packet.packet_type == PtPacketType::Ovf {
            overflow_positions.push(packet.offset);
        }
    }

    let mut stats = TraceStats::default();
    stats.total_packets = packets.len();
    stats.total_branches = branches.len();
    stats.taken_branches = branches.iter().filter(|b| b.taken).count();
    stats.not_taken_branches = branches.iter().filter(|b| !b.taken).count();
    for packet in &packets {
        let type_name = format!("{:?}", packet.packet_type);
        *stats.packets_by_type.entry(type_name).or_insert(0) += 1;
    }

    Ok(DecodedTrace {
        trace_id: String::new(),
        packets,
        branches,
        timing_events,
        mode_changes,
        cr3_changes,
        vmcs_changes,
        ptwrites,
        overflow_positions,
        errors: decoder.get_errors().to_vec(),
        stats,
    })
}
