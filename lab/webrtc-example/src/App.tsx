import {
  useRef,
  useState,
  type ChangeEventHandler,
  type MouseEventHandler,
} from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "./assets/vite.svg";
import heroImg from "./assets/hero.png";
import "./App.css";
import * as sdpTransform from "sdp-transform";

function App() {
  const pcRef = useRef<RTCPeerConnection>(null);
  const dcRef = useRef<RTCDataChannel>(null);
  const [localStream, setLocalStream] = useState<MediaStream>();
  const [sdpOffer, setSdpOffer] = useState<string>();
  const [sdpAnswer, setSdpAnswer] = useState<string>();

  const handleCreatePc = async () => {
    const pc = new RTCPeerConnection();
    pcRef.current = pc;
    console.log("pc created");
  };

  const handleCreateOffer = async () => {
    const pc = pcRef.current;

    if (!pc) {
      return;
    }

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    const sdpOffer = JSON.stringify(offer, null, 2);
    setSdpOffer(sdpOffer);
    console.log("offer created", sdpTransform.parse(offer.sdp!));
  };

  const handleCreateAnswer = async () => {
    const pc = pcRef.current;

    if (!pc || !sdpOffer) {
      return;
    }

    await pc.setRemoteDescription(JSON.parse(sdpOffer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    const sdpAnswer = JSON.stringify(answer, null, 2);
    setSdpAnswer(sdpAnswer);

    console.log("answer created", sdpTransform.parse(answer.sdp!));
  };

  const handleSetAnswer = async () => {
    const pc = pcRef.current;

    if (!pc || !sdpAnswer) {
      return;
    }

    await pc.setRemoteDescription(JSON.parse(sdpAnswer));

    console.log("answer set", sdpTransform.parse(sdpAnswer));
  };

  const handleChangeOffer: ChangeEventHandler<HTMLTextAreaElement> = async (
    e,
  ) => {
    setSdpOffer(e.target.value);
  };

  const handleChangeAnswer: ChangeEventHandler<HTMLTextAreaElement> = async (
    e,
  ) => {
    setSdpAnswer(e.target.value);
  };

  const handleCreateDc = async () => {
    const pc = pcRef.current;

    if (!pc) {
      return;
    }

    const dc = pc.createDataChannel("webrtc-example");
    dc.onerror = (error) => {
      console.error("data channel error", error);
    };
    dc.onmessage = (e) => {
      console.log("data channel message", e);
    };
    dc.onclose = (e) => {
      console.log("data channel close", e);
    };
    dcRef.current = dc;

    console.log("dc created");
  };

  const handleGetUserMedia = async () => {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: true,
    });
    setLocalStream(stream);

    console.log("got user media");
  };

  const handleAddTracks = async () => {
    const pc = pcRef.current;

    if (!pc || !localStream) {
      return;
    }

    for (const track of localStream.getTracks()) {
      pc.addTrack(track, localStream);
    }

    console.log("tracks added");
  };

  return (
    <>
      <button onClick={handleCreatePc}>create pc</button>
      <textarea
        onChange={handleChangeOffer}
        value={sdpOffer ? JSON.stringify(sdpOffer, null, 2) : ""}
        rows={10}
      ></textarea>
      <button onClick={handleCreateOffer}>create offer</button>
      <button onClick={handleCreateAnswer}>create answer</button>
      <textarea
        onChange={handleChangeAnswer}
        value={sdpAnswer ? JSON.stringify(sdpAnswer, null, 2) : ""}
        rows={10}
      ></textarea>
      <button onClick={handleSetAnswer}>set answer</button>
      <button onClick={handleGetUserMedia}>get user media</button>
      <button onClick={handleCreateDc}>create dc</button>
      <button onClick={handleAddTracks}>add tracks</button>
    </>
  );
}

export default App;
