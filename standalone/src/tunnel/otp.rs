/// DrayTek Vigor VPN 2FA (OTP/TOTP) over the established tunnel.
///
/// After the PPP tunnel is up, the router serves a web page at
/// `http://<gateway>/vpnmfa.htm?ifno=<N>&otp=&act=0` for any connected VPN user
/// that has 2FA enabled. Detection is via a 302 redirect from `GET /`.
/// Verification is a plain-HTTP GET to `vpnmfa.cgi`.
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::glib_channels::GlibSender;
use crate::messages::TunnelStatus;

/// HTTP/1.0 GET to the router management interface (plain HTTP on port 80).
/// Returns (status_code, headers_string).
async fn http_get(gateway: Ipv4Addr, path: &str) -> Result<(u16, String)> {
    let addr = SocketAddr::V4(SocketAddrV4::new(gateway, 80));
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("OTP HTTP connect timeout"))??;

    let request = format!("GET {path} HTTP/1.0\r\nHost: {gateway}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut raw: Vec<u8> = Vec::with_capacity(2048);
    let mut buf = [0u8; 512];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > 32_768 {
            break;
        }
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let headers = String::from_utf8_lossy(&raw[..header_end]).into_owned();

    let status: u16 = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok((status, headers))
}

/// Parse `key=value` from a URL query string. Returns the value slice.
fn query_param<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query = url.split_once('?')?.1;
    for part in query.split('&') {
        if let Some(val) = part.strip_prefix(&format!("{key}=")) {
            return Some(val.split('&').next().unwrap_or(val));
        }
    }
    None
}

/// GET the gateway root and check for a 302 redirect to vpnmfa.htm.
/// Returns `Some(ifno)` if OTP is required, `None` otherwise.
async fn detect_otp(gateway: Ipv4Addr) -> Result<Option<u32>> {
    let (status, headers) = http_get(gateway, "/").await?;
    if status != 302 {
        return Ok(None);
    }
    for line in headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            let loc = line["location:".len()..].trim();
            if loc.contains("vpnmfa.htm") {
                if let Some(n) = query_param(loc, "ifno").and_then(|v| v.parse::<u32>().ok()) {
                    return Ok(Some(n));
                }
            }
        }
    }
    Ok(None)
}

/// Submit the OTP code to vpnmfa.cgi.
/// Router responds 200 = accepted, 201 = rejected.
async fn submit_otp(gateway: Ipv4Addr, ifno: u32, code: &str) -> Result<bool> {
    let clean: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    let path = format!("/vpnmfa.cgi?act=0&ifno={ifno}&otp={clean}&sec=");
    let (status, _) = http_get(gateway, &path).await?;
    Ok(status == 200)
}

/// Entry point: detect OTP requirement, prompt the user, verify code.
///
/// Runs as a tokio task in parallel with the data loop.
/// `otp_rx` receives the user's answer: `Some(code)` or `None` (cancelled).
pub async fn check_and_authenticate(
    gateway: Ipv4Addr,
    status_tx: GlibSender<TunnelStatus>,
    otp_rx: tokio::sync::oneshot::Receiver<Option<String>>,
) {
    // Wait briefly for TUN routing to settle before making HTTP requests.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let ifno = match detect_otp(gateway).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            info!("OTP: not required for this connection");
            return;
        }
        Err(e) => {
            warn!("OTP: detection failed (continuing without 2FA): {e:#}");
            return;
        }
    };

    info!("OTP: 2FA required, ifno={ifno}");
    status_tx.send(TunnelStatus::OtpRequired { ifno });

    let answer = match otp_rx.await {
        Ok(a) => a,
        Err(_) => return, // Sender dropped — tunnel disconnecting
    };

    let code = match answer {
        Some(c) => c,
        None => {
            info!("OTP: user skipped 2FA");
            return;
        }
    };

    info!("OTP: submitting code for ifno={ifno}");
    match submit_otp(gateway, ifno, &code).await {
        Ok(true) => {
            info!("OTP: 2FA accepted");
            status_tx.send(TunnelStatus::OtpVerified);
        }
        Ok(false) => {
            warn!("OTP: 2FA rejected by router");
            status_tx.send(TunnelStatus::OtpFailed);
        }
        Err(e) => {
            warn!("OTP: submission error: {e:#}");
            status_tx.send(TunnelStatus::OtpFailed);
        }
    }
}
