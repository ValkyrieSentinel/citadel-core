#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_addr: u32,
    pub dest_port: u16,
    pub ttl: u8,
    pub window: u16,
}
