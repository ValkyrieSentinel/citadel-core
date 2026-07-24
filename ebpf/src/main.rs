#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use core::ptr::read_unaligned;
use citadel_core_common::PacketInfo;

#[map]
static EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::new(0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn citadel_core(ctx: XdpContext) -> u32 {
    match parse_packet(&ctx) {
        Ok(Some(info)) => {
            EVENTS.output(&ctx, &info, 0);
            xdp_action::XDP_PASS
        }
        _ => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn parse_packet(ctx: &XdpContext) -> Result<Option<PacketInfo>, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let mut offset: usize = 0;

    if start + offset + 14 > end {
        return Ok(None);
    }

    let mut eth_type = unsafe {
        u16::from_be(read_unaligned((start + offset + 12) as *const u16))
    };
    offset += 14;

    
    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        if start + offset + 4 > end {
            return Ok(None);
        }
        eth_type = unsafe {
            u16::from_be(read_unaligned((start + offset + 2) as *const u16))
        };
        offset += 4;
    }


    if eth_type != ETH_P_IP {
        return Ok(None);
    }


    if start + offset + 20 > end {
        return Ok(None);
    }

    let ver_ihl = unsafe { read_unaligned((start + offset) as *const u8) };
    let ihl = ((ver_ihl & 0x0F) as usize) * 4;

    
    if ihl < 20 || start + offset + ihl > end {
        return Ok(None);
    }

    
    let ttl = unsafe { read_unaligned((start + offset + 8) as *const u8) };
    let protocol = unsafe { read_unaligned((start + offset + 9) as *const u8) };
    let src_addr = unsafe {
        u32::from_be(read_unaligned((start + offset + 12) as *const u32))
    };

    
    offset += ihl;

    
    let mut dest_port = 0u16;
    if protocol == IPPROTO_TCP || protocol == IPPROTO_UDP {
        if start + offset + 4 <= end {
            dest_port = unsafe {
                u16::from_be(read_unaligned((start + offset + 2) as *const u16))
            };
        }
    }

    Ok(Some(PacketInfo {
        src_addr,
        dest_port,
        ttl,
        window: 0,
    }))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
