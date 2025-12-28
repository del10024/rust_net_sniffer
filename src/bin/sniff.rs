//! 网络嗅探工具（Windows NPF接口终极适配版）
use clap::Parser;
use pnet::datalink::{self, Config, Channel, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::Packet;
use rust_net_sniffer::{find_target_interface, SnifferError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true, help = "目标接口的IPv4地址（如10.16.26.148）")]
    ip: String,
}

// 全局退出标志（原子类型，线程安全）
static RUNNING: AtomicBool = AtomicBool::new(true);

/// 注册Ctrl+C信号处理（优雅退出）
fn setup_signal_handler() -> Result<(), SnifferError> {
    let running = Arc::new(&RUNNING);
    ctrlc::set_handler(move || {
        println!("\n⚠️  收到退出信号（Ctrl+C），正在释放资源...");
        running.store(false, Ordering::Relaxed);
    })
    .map_err(|e| SnifferError::SignalHandlerSetupFailed(e.to_string()))
}

/// 解析以太网帧并格式化输出
fn parse_ethernet_frame(frame: &EthernetPacket) {
    let src_mac = hex::encode(frame.get_source().octets());
    let dst_mac = hex::encode(frame.get_destination().octets());
    let ether_type = frame.get_ethertype();

    // 识别负载协议类型
    let payload_type = match ether_type {
        EtherTypes::Ipv4 => "IPv4",
        EtherTypes::Ipv6 => "IPv6",
        EtherTypes::Arp => "ARP",
        _ => "未知协议",
    };

    // 格式化输出帧信息
    println!("======================================");
    println!("📦 捕获以太网帧");
    println!("  - 目的MAC：{}（格式：{}）", dst_mac, format_mac(&dst_mac));
    println!("  - 源MAC：{}（格式：{}）", src_mac, format_mac(&src_mac));
    println!("  - 协议类型：{:?}", ether_type);
    println!("  - 负载类型：{}", payload_type);
    println!("  - 帧长度：{} 字节（帧头14字节 + 负载{}字节）",
             frame.packet().len(),
             frame.payload().len());
    println!("======================================\n");
}

/// 辅助函数：格式化MAC地址（000c296810f2 → 00:0c:29:68:10:f2）
fn format_mac(mac_str: &str) -> String {
    mac_str.as_bytes()
        .chunks(2)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(":")
}

/// 捕获并解析数据包（核心逻辑：适配NPF接口的阻塞读取）
fn capture_packets(interface: &NetworkInterface) -> Result<(), SnifferError> {
    // 配置通道（启用混杂模式）
    let config = Config {
        promiscuous: true,
        ..Default::default()
    };

    // 创建数据链路通道（匹配Ethernet枚举）
    let (_, mut rx) = match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(SnifferError::UnsupportedChannelType),
        Err(e) => return Err(SnifferError::ChannelCreationFailed(e.to_string())),
    };

    // 启动提示
    println!("✅ 网络嗅探工具启动成功！");
    println!("📌 监听NPF接口：{}", interface.name);
    println!("📌 接口对应IP：{}", interface.ips.iter().find(|ip| !ip.ip().is_unspecified()).unwrap().ip());
    println!("📌 模式：混杂模式（捕获所有流经接口的以太网帧）");
    println!("ℹ️  按 Ctrl+C 终止工具\n");

    // 循环捕获数据包（阻塞读取+信号中断）
    while RUNNING.load(Ordering::Relaxed) {
        match rx.next() { // Pnet 0.35.0原生next方法（无参数）
            Ok(buf) => {
                if let Some(frame) = EthernetPacket::new(&buf) {
                    parse_ethernet_frame(&frame);
                } else {
                    eprintln!("⚠️  {}", SnifferError::FrameParseFailed);
                }
            }
            Err(e) => {
                if RUNNING.load(Ordering::Relaxed) {
                    eprintln!("⚠️  {}", SnifferError::PacketReadFailed(e.to_string()));
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), SnifferError> {
    // 调试：打印Pnet枚举的所有接口（方便排查）
    println!("=== Pnet枚举的所有接口 ===");
    let pnet_interfaces = pnet::datalink::interfaces();
    for (i, iface) in pnet_interfaces.iter().enumerate() {
        println!("序号{}：名称={}, IP={:?}", 
                 i, iface.name, iface.ips.iter().map(|ip| ip.ip()).collect::<Vec<_>>());
    }
    println!("==========================\n");

    // 解析参数+查找接口+启动捕获
    let args = Args::parse();
    let interface = find_target_interface(&args.ip)?;
    setup_signal_handler()?;
    capture_packets(&interface)?;

    println!("👋 嗅探工具已正常退出，所有资源已释放");
    Ok(())
}