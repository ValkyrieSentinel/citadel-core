#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use citadel_core_common::PacketInfo;

#[map]
static EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::new(0);

#[xdp]
pub fn citadel_core(ctx: XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();

    
    if start + 14 > end { return xdp_action::XDP_PASS; }
    let eth_type = unsafe { u16::from_be(*( (start + 12) as *const u16 )) };
    if eth_type != 0x0800 { return xdp_action::XDP_PASS; }

    
    let ip_start = start + 14;
    if ip_start + 20 > end { return xdp_action::XDP_PASS; }
    
    let src_addr = unsafe { *( (ip_start + 12) as *const u32 ) };
    let ttl = unsafe { *( (ip_start + 8) as *const u8 ) };
    let protocol = unsafe { *( (ip_start + 9) as *const u8 ) };

  
    let mut dest_port = 0u16;
    if protocol == 6 || protocol == 17 {
        let transport_start = ip_start + 20;
        if transport_start + 4 <= end {
            dest_port = unsafe { u16::from_be(*( (transport_start + 2) as *const u16 )) };
        }
    }

    let info = PacketInfo {
        src_addr: u32::from_be(src_addr),
        dest_port,
        ttl,
        window: 0, 
    };

    EVENTS.output(&ctx, &info, 0);
    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
