import { useRef, useState } from "react";
import * as sdpTransform from "sdp-transform";

function isValidIPv4(ip: string) {
  const ipv4Regex =
    /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

const rtcConfig: RTCConfiguration = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
};

const signalingServerUrl = "http://localhost:3001";

type SdpMessage = {
  sessionId: string;
  medias: SdpMedia[];
};

type SdpMedia = {
  mediaId: string;
  mediaType: MediaType;
  direction: MediaDirection;
  ufrag: string;
  pwd: string;
  fingerprintType: FingerprintType;
  fingerprintHash: string;
  candidates: SdpMediaCandidate[];
  payloads: string;
  rtp: Rtp[];
  rtcpMux?: "rtcp-mux";
  protocol: string;
  sctpPort?: number;
  maxMessageSize?: number;
};

type Rtp = {
  payload: number;
  codec: string;
  rate: number;
};

type SdpMediaCandidate = {
  ip: string;
  port: number;
  candidateType: CandidateType;
  transportType: TransportType;
};

type MediaType = "audio" | "video";
type MediaDirection = "sendrecv" | "sendonly" | "recvonly" | "inactive";
type CandidateType = "host";
type TransportType = "udp" | "tcp";
type FingerprintType = "sha-256";

async function fetchSdpOffer(): Promise<SdpMessage> {
  const resp = await fetch(`${signalingServerUrl}/`);
  if (!resp.ok) {
    throw new Error("failed to fetch offer");
  }

  const offer = (await resp.json()) as SdpMessage;

  console.log("fetched sdp offer", offer);
  return offer;
}

async function sendSdpAnswer(
  answer: sdpTransform.SessionDescription,
): Promise<void> {
  console.log({ answer });
  const payload: SdpMessage = {
    sessionId: String(answer.origin.sessionId),
    medias:
      answer.media?.map((m) => ({
        mediaId: String(m.mid!),
        mediaType: m.type as MediaType,
        direction: m.direction ? (m.direction as MediaDirection) : "sendrecv",
        ufrag: m.iceUfrag!,
        pwd: m.icePwd!,
        fingerprintType: m.fingerprint!.type as FingerprintType,
        fingerprintHash: m.fingerprint!.hash,
        candidates:
          m.candidates
            ?.filter((c) => isValidIPv4(c.ip))
            .map((c) => ({
              ip: c.ip,
              port: c.port,
              candidateType: "host" as CandidateType,
              transportType: c.transport as TransportType,
            })) ?? [],
        payloads: "",
        rtp: [],
        protocol: m.protocol,
      })) ?? [],
  };

  const resp = await fetch(`${signalingServerUrl}/`, {
    headers: {
      "Content-Type": "application/json",
    },
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const responseBody = await resp.text();
    throw new Error(
      `failed to post answer: ${resp.status} ${resp.statusText} ${responseBody}`,
    );
  }

  const json = await resp.json();
  console.log("sent sdp answer", json);
  return json;
}

async function waitForIceGatheringComplete(
  pc: RTCPeerConnection,
  timeoutMs = 5000,
): Promise<void> {
  if (pc.iceGatheringState === "complete") {
    return;
  }

  await new Promise<void>((resolve) => {
    const onStateChange = () => {
      if (pc.iceGatheringState === "complete") {
        cleanup();
        resolve();
      }
    };

    const timeoutId = window.setTimeout(() => {
      cleanup();
      resolve();
    }, timeoutMs);

    const cleanup = () => {
      window.clearTimeout(timeoutId);
      pc.removeEventListener("icegatheringstatechange", onStateChange);
    };

    pc.addEventListener("icegatheringstatechange", onStateChange);
  });
}

function App() {
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const dcRef = useRef<RTCDataChannel | null>(null);
  const statsTimerRef = useRef<number | null>(null);
  const [iceCandidates, setIceCandidates] = useState<RTCIceCandidate[]>([]);
  const [pcReady, setPcReady] = useState(false);
  const [dcReady, setDcReady] = useState(false);
  const [dcMessage, setDcMessage] = useState("");
  const [dcLog, setDcLog] = useState<string[]>([]);

  const handleCreatePc = async () => {
    if (statsTimerRef.current !== null) {
      window.clearInterval(statsTimerRef.current);
      statsTimerRef.current = null;
    }
    if (pcRef.current) {
      pcRef.current.close();
      pcRef.current = null;
    }
    setPcReady(false);
    setDcReady(false);
    if (dcRef.current) {
      dcRef.current.close();
      dcRef.current = null;
    }

    const pc = new RTCPeerConnection(rtcConfig);
    pcRef.current = pc;

    // fetch offer
    const offer = await fetchSdpOffer();
    const offerStr = sdpTransform.write({
      version: 0,
      name: "-",
      origin: {
        username: "-",
        sessionId: offer.sessionId,
        sessionVersion: 2,
        netType: "IN",
        ipVer: 4,
        address: "127.0.0.1",
      },
      timing: {
        start: 0,
        stop: 0,
      },
      setup: "actpass",
      iceOptions: "trickle",
      groups: [
        {
          type: "BUNDLE",
          mids: offer.medias.map((media) => media.mediaId).join(" "),
        },
      ],
      media: offer.medias.map((media) => ({
        // sdp-transform expects codec name and rate separately.
        // Server sends "VP8/90000", so split it if needed.
        mid: media.mediaId,
        type: media.mediaType,
        direction: "recvonly",
        port: 9,
        rtcpMux: media.rtcpMux,
        protocol: media.protocol,
        payloads: media.payloads,
        connection: {
          version: 4,
          ip: "0.0.0.0",
        },
        iceUfrag: media.ufrag,
        icePwd: media.pwd,
        fingerprint: {
          type: media.fingerprintType,
          hash: media.fingerprintHash,
        },
        candidates: media.candidates.map((candidate) => ({
          foundation: "0",
          component: 1,
          transport: candidate.transportType,
          priority: 2113667327,
          ip: candidate.ip,
          port: candidate.port,
          type: candidate.candidateType,
        })),
        rtp:
          media.rtp.length > 0
            ? [
                {
                  payload: media.rtp[0].payload,
                  codec: media.rtp[0].codec,
                  rate: media.rtp[0].rate,
                },
              ]
            : [],
        fmtp: [],
      })),
    });
    await pc.setRemoteDescription({
      type: "offer",
      sdp: offerStr,
    });

    const offeredVideoTransceiver = pc.getTransceivers().find((transceiver) => {
      if (transceiver.mid && transceiver.mid === offer.medias[0]?.mediaId) {
        return true;
      }
      return transceiver.receiver.track.kind === "video";
    });

    if (!offeredVideoTransceiver) {
      throw new Error("missing offered video transceiver");
    }

    offeredVideoTransceiver.direction = "sendonly";

    // create data channel
    const dc = pc.createDataChannel("data");
    dcRef.current = dc;
    dc.onopen = () => {
      console.log("data channel opened");
      setDcReady(true);
      setDcLog((prev) => [...prev, "[system] data channel opened"]);
    };
    dc.onclose = () => {
      console.log("data channel closed");
      setDcReady(false);
      setDcLog((prev) => [...prev, "[system] data channel closed"]);
    };
    dc.onmessage = (ev) => {
      console.log("data channel message", ev.data);
      setDcLog((prev) => [...prev, `[recv] ${ev.data}`]);
    };
    dc.onerror = (ev) => {
      console.error("data channel error", ev);
      setDcLog((prev) => [...prev, `[error] ${ev}`]);
    };

    // {
    //   const offer = await pc.createOffer();
    //   console.log(sdpTransform.parse(offer.sdp!));

    //   const answer = await pc.createAnswer();
    //   console.log(sdpTransform.parse(answer.sdp!));
    // }

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitForIceGatheringComplete(pc);

    if (!pc.localDescription?.sdp) {
      throw new Error("missing localDescription SDP after createAnswer");
    }

    const sdpAnswer = sdpTransform.parse(pc.localDescription.sdp);
    console.log("localDescription.sdp", pc.localDescription.sdp);
    for (const transceiver of pc.getTransceivers()) {
      console.log("transceiver state", {
        mid: transceiver.mid,
        direction: transceiver.direction,
        currentDirection: transceiver.currentDirection,
        senderTrackKind: transceiver.sender.track?.kind,
        senderTrackReadyState: transceiver.sender.track?.readyState,
        receiverTrackKind: transceiver.receiver.track.kind,
      });
    }
    console.log({ sdpAnswer });
    await sendSdpAnswer(sdpAnswer);

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        setIceCandidates((value) => [...value, candidate]);
      }
    };

    pc.onconnectionstatechange = (ev) => {
      console.log("connection state changed", ev);
    };

    pc.oniceconnectionstatechange = (ev) => {
      console.log("ice connection state changed", ev);
    };

    pc.onicecandidateerror = (ev) => {
      console.log("ice candidate error", ev);
    };

    pc.onicegatheringstatechange = (ev) => {
      console.log("ice gathering state changed", ev);
    };

    pc.onsignalingstatechange = (ev) => {
      console.log("signaling state changed", ev);
    };

    statsTimerRef.current = window.setInterval(async () => {
      if (!pcRef.current) {
        return;
      }

      const stats = await pcRef.current.getStats();
      for (const report of stats.values()) {
        if (report.type === "outbound-rtp" && report.kind === "video") {
          console.log("outbound video stats", {
            bytesSent: report.bytesSent,
            packetsSent: report.packetsSent,
            framesEncoded:
              "framesEncoded" in report ? report.framesEncoded : undefined,
          });
        }
        if (
          report.type === "candidate-pair" &&
          report.state === "succeeded" &&
          "nominated" in report &&
          report.nominated
        ) {
          console.log("selected candidate pair", {
            localCandidateId: report.localCandidateId,
            remoteCandidateId: report.remoteCandidateId,
            bytesSent: report.bytesSent,
            bytesReceived: report.bytesReceived,
          });
        }
      }
    }, 2000);

    setPcReady(true);
  };

  const handleStartMedia = async () => {
    const pc = pcRef.current;
    if (!pc) {
      throw new Error("peer connection is not created yet");
    }

    const stream = await navigator.mediaDevices.getUserMedia({
      video: true,
      audio: false,
    });

    if (localVideoRef.current) {
      localVideoRef.current.srcObject = stream;
    }

    const offeredVideoTransceiver = pc.getTransceivers().find((transceiver) => {
      return transceiver.receiver.track.kind === "video";
    });

    if (!offeredVideoTransceiver) {
      throw new Error("missing offered video transceiver");
    }

    const videoTrack = stream.getVideoTracks()[0] ?? null;
    if (!videoTrack) {
      throw new Error("missing local video track");
    }

    await offeredVideoTransceiver.sender.replaceTrack(videoTrack);
    offeredVideoTransceiver.sender.setStreams(stream);
    console.log("media started; track attached to transceiver");
  };

  const handleSendMessage = () => {
    const dc = dcRef.current;
    if (!dc || dc.readyState !== "open") {
      console.warn("data channel is not open");
      return;
    }
    if (!dcMessage.trim()) {
      return;
    }
    dc.send(dcMessage);
    setDcLog((prev) => [...prev, `[send] ${dcMessage}`]);
    setDcMessage("");
  };

  return (
    <div>
      <div>
        <h3>Local Video</h3>
        <video ref={localVideoRef} autoPlay playsInline muted>
          <track kind="captions" />
        </video>
      </div>
      <div>
        <button type="button" onClick={handleCreatePc}>
          create pc
        </button>
        <button type="button" onClick={handleStartMedia} disabled={!pcReady}>
          start media
        </button>
      </div>
      <div>
        <h3>Data Channel</h3>
        <div>
          <input
            type="text"
            value={dcMessage}
            onChange={(e) => setDcMessage(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSendMessage();
            }}
            placeholder="type a message..."
            disabled={!dcReady}
          />
          <button type="button" onClick={handleSendMessage} disabled={!dcReady}>
            send
          </button>
        </div>
        <textarea readOnly rows={8} value={dcLog.join("\n")} />
      </div>
      <div>
        <label>ice candidates</label>
        <textarea
          readOnly
          rows={4}
          value={JSON.stringify(iceCandidates, null, 2)}
        />
      </div>
    </div>
  );
}

export default App;
