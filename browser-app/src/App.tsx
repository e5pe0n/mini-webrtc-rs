import { useRef, useState } from "react";
import * as sdpTransform from "sdp-transform";

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
  ufrag: string;
  pwd: string;
  fingerprintType: FingerprintType;
  fingerprintHash: string;
  candidates: SdpMediaCandidate[];
  payloads: string;
  rtpCodec: string;
};

type SdpMediaCandidate = {
  ip: string;
  port: number;
  candidateType: CandidateType;
  transportType: TransportType;
};

type MediaType = "audio" | "video";
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
  const payload: SdpMessage = {
    sessionId: String(answer.origin.sessionId),
    medias:
      answer.media?.map((m) => ({
        mediaId: String(m.mid ?? "0"),
        mediaType: m.type === "audio" ? "audio" : "video",
        ufrag: String(m.iceUfrag ?? ""),
        pwd: String(m.icePwd ?? ""),
        fingerprintType: "sha-256",
        fingerprintHash: String(m.fingerprint?.hash ?? ""),
        candidates:
          m.candidates?.map((c) => ({
            ip: String(c.ip),
            port: Number(c.port),
            candidateType: "host",
            transportType:
              String(c.transport).toLowerCase() === "tcp" ? "tcp" : "udp",
          })) ?? [],
        payloads: String(m.payloads ?? ""),
        rtpCodec: (() => {
          const firstRtp = m.rtp?.[0];
          if (!firstRtp?.codec) {
            return "";
          }
          const rate = firstRtp.rate ?? 90000;
          return `${firstRtp.codec}/${rate}`;
        })(),
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
  const [iceCandidates, setIceCandidates] = useState<RTCIceCandidate[]>([]);

  const handleStartMedia = async () => {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: true,
      audio: true,
    });

    if (localVideoRef.current) {
      localVideoRef.current.srcObject = stream;
    }

    const pc = new RTCPeerConnection(rtcConfig);

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
      media: offer.medias.map((media) => ({
        // sdp-transform expects codec name and rate separately.
        // Server sends "VP8/90000", so split it if needed.
        mid: media.mediaId,
        type: media.mediaType,
        port: 9,
        rtcpMux: "rtcp-mux",
        protocol: "UDP/TLS/RTP/SAVPF",
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
        rtp: [
          {
            payload: Number.parseInt(media.payloads, 10),
            codec: media.rtpCodec.split("/")[0],
            rate: Number.parseInt(media.rtpCodec.split("/")[1] ?? "90000", 10),
            encoding: media.rtpCodec.split("/")[2]
              ? Number.parseInt(media.rtpCodec.split("/")[2], 10)
              : undefined,
          },
        ],
        fmtp: [],
      })),
    });
    await pc.setRemoteDescription({
      type: "offer",
      sdp: offerStr,
    });

    for (const track of stream.getTracks()) {
      pc.addTrack(track, stream);
    }

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitForIceGatheringComplete(pc);

    if (!pc.localDescription?.sdp) {
      throw new Error("missing localDescription SDP after createAnswer");
    }

    const sdpAnswer = sdpTransform.parse(pc.localDescription.sdp);
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
        <button type="button" onClick={handleStartMedia}>
          start media
        </button>
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
