//! 网络工具公共逻辑库（适配Windows NPF接口）
use pnet::datalink::NetworkInterface;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnifferError {
    #[error("未找到IP为{0}的有效网络接口（请确认IP正确）")]
    InterfaceNotFound(String),

    #[error("创建数据链路通道失败：{0}")]
    ChannelCreationFailed(String),

    #[error("读取数据包失败：{0}")]
    PacketReadFailed(String),

    #[error("解析以太网帧失败（无效格式）")]
    FrameParseFailed,

    #[error("注册退出信号失败：{0}")]
    SignalHandlerSetupFailed(String),

    #[error("仅支持以太网通道，不支持其他类型通道")]
    UnsupportedChannelType,
}

/// 按IP地址查找网络接口（适配Windows NPF接口格式）
/// 参数：target_ip - 目标接口的IPv4地址（如"10.16.26.148"）
pub fn find_target_interface(target_ip: &str) -> Result<NetworkInterface, SnifferError> {
    pnet::datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            // 核心适配：忽略Pnet失效的is_up()，仅过滤回环+匹配IP
            !iface.is_loopback() 
            && iface.ips.iter().any(|ip| {
                ip.ip().to_string() == target_ip // 精准匹配IPv4地址
            })
        })
        .next()
        .ok_or_else(|| SnifferError::InterfaceNotFound(target_ip.to_string()))
}