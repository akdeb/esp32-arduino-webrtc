'use strict';
const $ = id => document.getElementById(id);
let peer, stream, statsTimer, controller;
let generation = 0;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function api(path, method = 'GET', body, signal) {
  const response = await fetch(`/api/${path}`, {method, body, signal});
  if (!response.ok) throw new Error(`${path}: ${response.status} ${await response.text()}`);
  return response;
}
async function stop() {
  ++generation;
  controller?.abort(); controller = undefined;
  clearInterval(statsTimer);
  peer?.close(); peer = undefined;
  stream?.getTracks().forEach(track => track.stop()); stream = undefined;
  $('remote').srcObject = null;
  $('start').disabled = true; $('stop').disabled = true;
  try { await api('stop', 'POST'); } catch (error) { $('status').textContent = error.message; }
  finally { $('start').disabled = false; }
}
$('start').onclick = async () => {
  const run = ++generation;
  controller = new AbortController();
  const {signal} = controller;
  $('start').disabled = true; $('stop').disabled = false;
  try {
    const format = await (await api('config', 'GET', undefined, signal)).json();
    $('format').textContent = `${format.codec.toUpperCase()} · ESP32 PCM ${format.sampleRate / 1000} kHz mono · ${format.bitrate / 1000} kbit/s`;
    $('status').textContent = 'Requesting microphone…';
    const media = await navigator.mediaDevices.getUserMedia({audio: {channelCount: 1, sampleRate: format.sampleRate, echoCancellation: true, noiseSuppression: true}, video: false});
    if (run !== generation) { media.getTracks().forEach(track => track.stop()); return; }
    stream = media;
    const pc = peer = new RTCPeerConnection({iceServers: []});
    pc.ontrack = event => {
      $('remote').srcObject = event.streams[0] || new MediaStream([event.track]);
      $('remote').play().catch(() => { $('status').textContent = 'Click Play on the audio control to hear the board.'; });
    };
    pc.onconnectionstatechange = () => { $('status').textContent = `Connection: ${pc.connectionState}`; };
    const transceiver = pc.addTransceiver(stream.getAudioTracks()[0], {direction: 'sendrecv', streams: [stream]});
    const codecs = RTCRtpSender.getCapabilities('audio').codecs.filter(codec => codec.mimeType.toLowerCase() === `audio/${format.codec}`);
    if (!codecs.length || !transceiver.setCodecPreferences) throw new Error(`This browser does not support selecting ${format.codec}. Use a recent Chromium or Firefox browser.`);
    transceiver.setCodecPreferences(codecs);
    const offer = await pc.createOffer();
    if (format.codec === 'opus') {
      offer.sdp = configureOpusSdp(offer.sdp, format);
    }
    await pc.setLocalDescription(offer);
    $('status').textContent = 'Gathering LAN candidates…';
    const gatheringDeadline = Date.now() + 15000;
    while (pc.iceGatheringState !== 'complete') {
      if (signal.aborted) return;
      if (Date.now() > gatheringDeadline) throw new Error('ICE gathering timed out');
      await sleep(100);
    }
    await api('offer', 'POST', pc.localDescription.sdp, signal);
    $('status').textContent = 'Waiting for ESP32 answer…';
    const deadline = Date.now() + 30000;
    let answered = false;
    while (!signal.aborted && Date.now() < deadline) {
      const response = await api('answer', 'GET', undefined, signal);
      if (response.status === 200) {
        await pc.setRemoteDescription({type: 'answer', sdp: await response.text()});
        answered = true; break;
      }
      await sleep(200);
    }
    if (signal.aborted) return;
    if (!answered) throw new Error('Board did not generate an SDP answer within 30 seconds');
    await api('mic', 'POST', $('mic').checked ? 'on' : 'off', signal);
    let fetching = false;
    statsTimer = setInterval(async () => {
      if (fetching) return;
      fetching = true;
      try { $('stats').textContent = JSON.stringify(await (await api('stats', 'GET', undefined, signal)).json(), null, 2); }
      catch (error) { if (!signal.aborted) $('stats').textContent = error.message; }
      finally { fetching = false; }
    }, 2000);
  } catch (error) {
    if (run !== generation) return;
    await stop(); $('status').textContent = error.message;
  }
};
$('stop').onclick = async () => { await stop(); $('status').textContent = 'Call ended.'; };
$('mic').onchange = async () => {
  try { await api('mic', 'POST', $('mic').checked ? 'on' : 'off'); }
  catch (error) { $('status').textContent = error.message; }
};
