'use strict';
// PCM bandwidth preferences do not change Opus's required opus/48000/2 rtpmap.
function configureOpusSdp(sdp, format) {
  const match = sdp.match(/^a=rtpmap:(\d+) opus\/48000\/2\r?$/im);
  if (!match) throw new Error('Browser offer has no standard Opus RTP mapping');
  const prefix = `a=fmtp:${match[1]} `;
  const settings = {
    stereo: '0', 'sprop-stereo': '0', usedtx: '0', useinbandfec: '0',
    maxaveragebitrate: String(format.bitrate),
    maxplaybackrate: String(format.sampleRate),
    'sprop-maxcapturerate': String(format.sampleRate)
  };
  const lines = sdp.split(/\r?\n/);
  const i = lines.findIndex(line => line.startsWith(prefix));
  const params = new Map();
  if (i >= 0) {
    for (const item of lines[i].slice(prefix.length).split(';')) {
      const [key, value] = item.trim().split('=');
      if (key) params.set(key, value);
    }
  }
  for (const [key, value] of Object.entries(settings)) params.set(key, value);
  const line = prefix + [...params].map(([key, value]) => `${key}=${value}`).join(';');
  if (i >= 0) lines[i] = line;
  else lines.splice(lines.findIndex(item => item.startsWith(`a=rtpmap:${match[1]} `)) + 1, 0, line);
  return lines.join('\r\n');
}
if (typeof module !== 'undefined') module.exports = {configureOpusSdp};
