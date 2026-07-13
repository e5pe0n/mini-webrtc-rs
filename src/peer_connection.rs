use crate::common::TransportMessage;
use crate::data_channel::DataChannel;
use crate::dtls::Fingerprint;
use crate::dtls::manager::DtlsManager;
use crate::ice::Peer;
use crate::internal_event::InternalEvent;
use crate::media_stream_track::{
    MediaStreamTrack, MediaStreamTrackKind, MediaStreamTrackReadyState,
};
use crate::rtc_event::{RtcEvent, RtcTrackEvent};
use crate::sctp::manager::SctpManager;
use crate::sdp::MediaType;
use crate::srtp::SrtpManager;
use crate::srtp::packet::RtpPacket;
use crate::{
    ice::{IceAgent, IceCandidate},
    signaling_server::SignalingServer,
    stun::StunClient,
    udp_server::UdpServer,
};
use anyhow::{Context, Result, anyhow};
use local_ip_address::local_ip;
use rcgen::generate_simple_self_signed;
use std::collections::VecDeque;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const UDP_SERVER_PORT: u64 = 4433;
const STUN_SERVER_ADDRESS: &'static str = "stun.l.google.com:19302";

pub struct PeerConnection {
    sctp_manager: Arc<Mutex<SctpManager>>,
    rtc_event_rx: mpsc::UnboundedReceiver<RtcEvent>,
    event_loop_handle: JoinHandle<Result<()>>,
    signaling_server_handle: JoinHandle<Result<()>>,
}

impl PeerConnection {
    pub async fn new() -> Result<Self> {
        tracing_subscriber::fmt::init();

        // Generate self-signed certificate
        let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let fingerprint = Fingerprint::new(certified_key.cert.der());

        let local_ip = local_ip().unwrap();
        info!("local_ip={local_ip:?}");

        let mut stun_addrs = STUN_SERVER_ADDRESS
            .to_socket_addrs()
            .context("resolve STUN server address")?;
        let stun_addr = stun_addrs
            .find(|addr| addr.is_ipv4())
            .or_else(|| stun_addrs.next())
            .ok_or(anyhow!("resolved STUN server address list is empty"))?;
        let stun_client = StunClient::new(stun_addr);

        let mut ice_candidates = vec![IceCandidate {
            ip: local_ip,
            port: UDP_SERVER_PORT,
        }];

        match stun_client.binding_request().await {
            Ok(mapped_address) => {
                info!("mapped_address={mapped_address:?}");
                ice_candidates.push(IceCandidate {
                    ip: mapped_address.ip(),
                    port: UDP_SERVER_PORT,
                });
            }
            Err(err) => {
                warn!("stun mapping failed; continue with host candidate only: {err}");
            }
        }

        let ice_agent = Arc::new(Mutex::new(IceAgent::new(
            ice_candidates,
            fingerprint.clone(),
        )));

        let internal_event_queue = Arc::new(Mutex::new(VecDeque::new()));
        let (rtc_event_tx, rtc_event_rx) = mpsc::unbounded_channel::<RtcEvent>();

        let mut dtls_manager =
            DtlsManager::new(certified_key, fingerprint, internal_event_queue.clone());
        let mut srtp_manager = SrtpManager::new(internal_event_queue.clone());
        let sctp_manager = SctpManager::new(internal_event_queue.clone());
        let sctp_manager = Arc::new(Mutex::new(sctp_manager));
        let sctp_manager_clone = sctp_manager.clone();

        let mut udp_server = UdpServer::new(
            &format!("0.0.0.0:{UDP_SERVER_PORT}"),
            ice_agent.clone(),
            internal_event_queue.clone(),
        )
        .await
        .context("init udp server")?;

        let internal_event_queue_clone = internal_event_queue.clone();

        let event_loop_handle = tokio::spawn(async move {
            let sctp_manager = sctp_manager_clone;
            loop {
                let next_event = internal_event_queue_clone.lock().await.pop_front();
                if let Some(event) = next_event {
                    match event {
                        InternalEvent::SdpAnswer(answer) => {
                            let remote_peers = answer
                                .medias
                                .iter()
                                .map(|media| Peer {
                                    ufrag: media.ufrag.clone(),
                                    pwd: media.pwd.clone(),
                                    fingerprint: media.fingerprint_hash.clone(),
                                })
                                .collect::<Vec<_>>();
                            udp_server.set_remote_peers(remote_peers).await;

                            for media in answer.medias {
                                match media.media_type {
                                    MediaType::Video => {
                                        let (inbound_rtp_tx, inbound_rtp_rx) =
                                            mpsc::unbounded_channel::<RtpPacket>();

                                        srtp_manager.set_media_track_transport(inbound_rtp_tx);
                                        let media_stream_tack = MediaStreamTrack {
                                            id: media.track_id.clone(),
                                            kind: MediaStreamTrackKind::try_from(media.media_type)?,
                                            label: media.track_id,
                                            ready_state: MediaStreamTrackReadyState::Live,
                                            inbound_rtp_rx,
                                        };

                                        if let Err(err) =
                                            rtc_event_tx.send(RtcEvent::RtcTrack(RtcTrackEvent {
                                                track: media_stream_tack,
                                            }))
                                        {
                                            warn!("failed to emit rtc track event: {err}");
                                        }
                                    }
                                    _ => {
                                        debug!("ignore media type: {:?}", media.media_type);
                                    }
                                }
                            }
                        }
                        InternalEvent::InboundDtlsPacket(TransportMessage { peer_addr, data }) => {
                            let _ = dtls_manager
                                .handle_inbound_packet(&data, peer_addr)
                                .await
                                .inspect_err(|err| warn!("{err:?}"));
                        }
                        InternalEvent::DtlsConnected(encryption_keys) => {
                            srtp_manager.set_encryption_keys(encryption_keys);
                        }
                        InternalEvent::InboundRtpPacket(TransportMessage { peer_addr, data }) => {
                            let _ = srtp_manager
                                .handle_inbound_packet(&data, peer_addr)
                                .inspect_err(|err| warn!("{err:?}"));
                        }
                        InternalEvent::InboundSctpPacket(TransportMessage { peer_addr, data }) => {
                            let _ = sctp_manager
                                .lock()
                                .await
                                .handle_inbound_packet(&data, peer_addr)
                                .await
                                .inspect_err(|err| warn!("{err:?}"));
                        }
                        InternalEvent::OutboundSctpPacket(TransportMessage {
                            peer_addr: _,
                            data,
                        }) => {
                            let _ = dtls_manager
                                .send_application_data(&data)
                                .await
                                .inspect_err(|err| warn!("{err:?}"));
                        }
                        InternalEvent::OutboundDtlsPacket(TransportMessage { peer_addr, data }) => {
                            let _ = udp_server
                                .send(&data, peer_addr)
                                .await
                                .inspect_err(|err| warn!("{err:?}"));
                        }
                    }
                } else {
                    select! {
                        _ = udp_server.recv() => {}
                    }
                }
            }
        });

        let signaling_server = SignalingServer::new(ice_agent, internal_event_queue).await;
        let signaling_server_handle = tokio::spawn(async move { signaling_server.run().await });

        Ok(Self {
            event_loop_handle,
            signaling_server_handle,
            sctp_manager,
            rtc_event_rx,
        })
    }

    pub async fn recv(&mut self) -> Option<RtcEvent> {
        self.rtc_event_rx.recv().await
    }

    pub fn close(self) {
        self.event_loop_handle.abort();
        self.signaling_server_handle.abort();
        drop(self);
    }

    pub async fn create_data_channel(&self) -> Result<DataChannel> {
        Ok(DataChannel::new(0, self.sctp_manager.clone()).await)
    }
}
