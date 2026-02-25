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
  mediaItems: SdpMedia[];
};

type SdpMedia = {
  mediaId: number;
  type: MediaType;
  ufrag: string;
  pwd: string;
  fingerprintType: FingerprintType;
  fingerprintHash: string;
  candidates: SdpMediaCandidate[];
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
  const resp = await fetch(`${signalingServerUrl}/offer`);
  if (!resp.ok) {
    throw new Error("failed to fetch offer");
  }

  return await resp.json();
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
      // TODO
    });
    pc.setRemoteDescription({
      type: "offer",
      sdp: offerStr,
    });
    // create answer
    // send answer

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
