import { useRef, useState } from "react";
import "./App.css";
import * as sdpTransform from "sdp-transform";

const rtcConfig: RTCConfiguration = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
};

const signalingServerUrl = "http://localhost:3000";

type SdpOffer = {
  sessionId: string;
  medias: SdpMedia[];
};

type SdpMedia = {
  mediaId: number;
  type: MediaType;
  ufrag: string;
  pwd: string;
  fingerprintType: FingerprintType;
  fingerprintHash: string;
  candidates: SdpMediaCandidate[];
  payloads: string;
  rtcCodec: string;
};

type SdpMediaCandidate = {
  ip: string;
  port: number;
  type: CandidateType;
  transport: TransportType;
};

type MediaType = "audio" | "video";
type CandidateType = "host";
type TransportType = "udp" | "tcp";
type FingerprintType = "sha-256";

async function fetchSdpOffer(): Promise<SdpOffer> {
  const resp = await fetch(`${signalingServerUrl}/`);
  if (!resp.ok) {
    throw new Error("failed to fetch offer");
  }

  const json = await resp.json();
  console.log("fetched sdp offer", json);
  return json;
}

async function sendSdpAnswer(
  answer: sdpTransform.SessionDescription,
): Promise<void> {
  const resp = await fetch(`${signalingServerUrl}/`, {
    method: "POST",
    body: JSON.stringify(answer),
  });
  if (!resp.ok) {
    throw new Error("failed to fetch offer");
  }

  const json = await resp.json();
  console.log("fetched sdp offer", json);
  return json;
}

function App() {
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const [peerConnection, setPeerConnection] =
    useState<RTCPeerConnection | null>(null);

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
      name: "",
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
        mid: String(media.mediaId),
        type: media.type,
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
          transport: candidate.transport,
          priority: 2113667327,
          ip: candidate.ip,
          port: candidate.port,
          type: candidate.type,
        })),
        rtp: [
          {
            payload: Number.parseInt(media.payloads),
            codec: media.rtcCodec,
          },
        ],
        fmtp: [],
      })),
    });
    pc.setRemoteDescription({
      type: "offer",
      sdp: offerStr,
    });
    const answer = await pc.createAnswer();
    const sdpAnswer = sdpTransform.parse(answer.sdp!);
    await sendSdpAnswer(sdpAnswer);
    pc.setLocalDescription(answer);

    for (const track of stream.getTracks()) {
      pc.addTrack(track, stream);
    }

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
