#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::XdpContext,
};
use core::ptr::read_unaligned;
use citadel_core_common::{PacketInfo, PacketStats};

#[map]
static EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::new(0);

#[map]
static DROP_LIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn citadel_core(ctx: XdpContext) -> u32 {
    match parse_packet(&ctx) {
        Ok((action, Some(info))) => {
            if action == xdp_action::XDP_PASS {
                EVENTS.output(&ctx, &info, 0);
            }
            action
        }
        Ok((action, None)) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn parse_packet(ctx: &XdpContext) -> Result<(u32, Option<PacketInfo>), ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let packet_len = (end - start) as u64;

    let mut offset: usize = 0;

    if start + offset + 14 > end {
        return Ok((xdp_action::XDP_PASS, None));
    }

    let mut eth_type = unsafe {
        u16::from_be(read_unaligned((start + offset + 12) as *const u16))
    };
    offset += 14;

    for _ in 0..2 {
        if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
            if start + offset + 4 > end {
                return Ok((xdp_action::XDP_PASS, None));
            }
            eth_type = unsafe {
                u16::from_be(read_unaligned((start + offset + 2) as *const u16))
            };
            offset += 4;
        } else {
            break;
        }
    }

    if eth_type != ETH_P_IP {
        return Ok((xdp_action::XDP_PASS, None));
    }

    if start + offset + 20 > end {
        return Ok((xdp_action::XDP_PASS, None));
    }

    let ver_ihl = unsafe { read_unaligned((start + offset) as *const u8) };
    let ihl = ((ver_ihl & 0x0F) as usize) * 4;

    if ihl < 20 || start + offset + ihl > end {
        return Ok((xdp_action::XDP_PASS, None));
    }

    let ttl = unsafe { read_unaligned((start + offset + 8) as *const u8) };
    let protocol = unsafe { read_unaligned((start + offset + 9) as *const u8) };
    let src_addr = unsafe {
        u32::from_be(read_unaligned((start + offset + 12) as *const u32))
    };

    if unsafe { DROP_LIST.get(&src_addr) }.is_some() {
        update_stats(packet_len, true);
        return Ok((xdp_action::XDP_DROP, None));
    }

    update_stats(packet_len, false);
    offset += ihl;

    let mut dest_port = 0u16;
    let mut window = 0u16;
    let mut tcp_flags = 0u8;

    if protocol == IPPROTO_TCP {
        if start + offset + 20 <= end {
            dest_port = unsafe {
                u16::from_be(read_unaligned((start + offset + 2) as *const u16))
            };
            tcp_flags = unsafe {
                read_unaligned((start + offset + 13) as *const u8)
            };
            window = unsafe {
                u16::from_be(read_unaligned((start + offset + 14) as *const u16))
            };
        }
    } else if protocol == IPPROTO_UDP {
        if start + offset + 8 <= end {
            dest_port = unsafe {
                u16::from_be(read_unaligned((start + offset + 2) as *const u16))
            };
        }
    }

    Ok((
        xdp_action::XDP_PASS,
        Some(PacketInfo {
            src_addr,
            dest_port,
            ttl,
            tcp_flags,
            window,
            _pad: 0,
        }),
    ))
}

#[inline(always)]
fn update_stats(bytes: u64, is_drop: bool) {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe {
            if is_drop {
                (*stats).dropped_packets += 1;
            } else {
                (*stats).rx_packets += 1;
                (*stats).rx_bytes += bytes;
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
