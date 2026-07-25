#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_addr: u32,
    pub dest_port: u16,
    pub ttl: u8,
    pub tcp_flags: u8,
    pub window: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
}
