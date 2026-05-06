use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dtls::{Fingerprint, manager::DtlsManager};
use rcgen::generate_simple_self_signed;
use tokio::net::UdpSocket;
use tokio::process::Command;

fn make_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("{}-{}-{}", prefix, std::process::id(), nanos));
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

async fn run_cmd(program: &str, args: &[&str], cwd: Option<&Path>) -> anyhow::Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let out = cmd.output().await?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    Ok(())
}

async fn has_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn openssl_client_can_reach_dtls_server_flights() -> anyhow::Result<()> {
    if !has_openssl().await {
        eprintln!("openssl not found; skipping interoperability test");
        return Ok(());
    }

    let tmp = make_temp_dir("dtls-openssl-interop");
    let client_key = tmp.join("client.key");
    let client_cert = tmp.join("client.crt");
    let client_der = tmp.join("client.der");

    let client_key_s = client_key.to_string_lossy().to_string();
    let client_cert_s = client_cert.to_string_lossy().to_string();
    let client_der_s = client_der.to_string_lossy().to_string();

    // Use an ECDSA certificate so CertificateVerify algorithm matches server expectations.
    run_cmd(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-sha256",
            "-nodes",
            "-keyout",
            &client_key_s,
            "-out",
            &client_cert_s,
            "-subj",
            "/CN=interop-client",
            "-days",
            "1",
        ],
        None,
    )
    .await?;

    run_cmd(
        "openssl",
        &[
            "x509",
            "-in",
            &client_cert_s,
            "-outform",
            "DER",
            "-out",
            &client_der_s,
        ],
        None,
    )
    .await?;

    let client_der_bytes = std::fs::read(&client_der)?;
    let expected_client_fingerprint = Fingerprint::new(&client_der_bytes);

    let server_certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_addr = server_socket.local_addr()?;

    let mut manager = DtlsManager::new(
        Arc::clone(&server_socket),
        server_certified_key,
        expected_client_fingerprint,
    );

    let mut received_packets = 0usize;

    let mut openssl = Command::new("openssl");
    openssl
        .args([
            "s_client",
            "-dtls1_2",
            "-connect",
            &server_addr.to_string(),
            "-cert",
            &client_cert_s,
            "-key",
            &client_key_s,
            "-cipher",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "-use_srtp",
            "SRTP_AEAD_AES_128_GCM",
            "-timeout",
            "-brief",
            "-msg",
            "-state",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = openssl.spawn()?;

    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline {
        let recv = tokio::time::timeout(
            Duration::from_millis(250),
            server_socket.recv_from(&mut buf),
        )
        .await;
        match recv {
            Ok(Ok((n, peer))) => {
                received_packets += 1;
                manager.handle_dtls_packet(&buf[..n], peer).await?;
            }
            Ok(Err(e)) => return Err(anyhow::anyhow!("server recv error: {e}")),
            Err(_) => {}
        }

        if child.try_wait()?.is_some() {
            break;
        }
    }

    if child.try_wait()?.is_none() {
        let _ = child.kill().await;
    }
    let output = child.wait_with_output().await?;

    let packets = received_packets;
    let openssl_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        packets >= 2,
        "expected at least 2 packets (ClientHello + cookie retry), got {packets}. openssl output:\n{openssl_output}"
    );

    assert!(
        openssl_output.contains("DTLS")
            || openssl_output.contains("SSL_connect")
            || openssl_output.contains("write client hello"),
        "openssl did not appear to perform DTLS handshake. output:\n{openssl_output}"
    );

    Ok(())
}
