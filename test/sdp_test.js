'use strict';
const assert = require('node:assert/strict');
const {configureOpusSdp} = require('../browser/sdp.js');
const base = 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n';
for(const rate of [16000,24000,48000]) {
  const result=configureOpusSdp(base,{sampleRate:rate,bitrate:48000});
  assert.match(result,/opus\/48000\/2/);
  assert.ok(result.includes(`maxplaybackrate=${rate}`));
  assert.ok(result.includes(`sprop-maxcapturerate=${rate}`));
  assert.ok(result.includes('maxaveragebitrate=48000'));
  assert.ok(result.includes('minptime=10'));
  assert.ok(result.includes('useinbandfec=0'));
  assert.equal(configureOpusSdp(result,{sampleRate:rate,bitrate:48000}),result);
}
assert.match(configureOpusSdp(base.replace(/^a=fmtp:.*\r\n/m,''),{sampleRate:24000,bitrate:48000}),/a=fmtp:111/);
assert.throws(()=>configureOpusSdp('v=0\r\n',{sampleRate:24000,bitrate:48000}));
console.log('PASS: browser Opus SDP keeps 48 kHz RTP clock, mono/rate/bitrate preferences, idempotent updates');
