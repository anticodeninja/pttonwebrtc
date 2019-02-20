// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

(function (){
    'use strict';

    let pttState = false,
        ctrClients = document.querySelector('#clients'),
        ctrDebugLog = document.querySelector('#debug-log'),
        ctrPtt = document.querySelector('#ptt'),
        socket,
        microphone,
        clients = {},
        transceiverPool = [],
        clientId = 0,
        serverIp = '127.0.0.1',
        serverPort = 18500,
        rtpSender,
        rtc;

    function log(value) {
        ctrDebugLog.value += value + '\n';
        ctrDebugLog.scrollTop = ctrDebugLog.scrollHeight
    }

    function updateClients(newClients) {
        let active = new Set();
        let updateSdp = false;

        for (let i = 0, len = newClients.length; i < len; ++i) {
            let nc = newClients[i];
            active.add(nc.id);

            let c = clients[nc.id];
            if (!c) {
                let ctrBlock = document.createElement('div');
                ctrBlock.innerHTML = '<span class="name"></span>' +
                                     '<span class="state"></span>' +
                                     '<audio autoplay controls></audio>';
                ctrClients.appendChild(ctrBlock);

                clients[nc.id] = c = {
                    id: nc.id,
                    ctrBlock: ctrBlock,
                }
            }

            if (rtc.connectionState == 'connected' && c.id != clientId && !c.transceiver) {
                updateSdp = true;
                c.transceiver = transceiverPool.length > 0
                    ? transceiverPool.pop()
                    : rtc.addTransceiver('audio', {direction: 'recvonly'});
            }

            c.ctrBlock.querySelector('.name').innerText = nc.name + (nc.id == clientId ? ' (me)' : '');
            c.ctrBlock.querySelector('.state').innerText = nc.state;

            if (c.transceiver) {
                c.ctrBlock.querySelector('audio').srcObject = new MediaStream([c.transceiver.receiver.track]);
            }
        }

        for (let cid in clients) {
            let c = clients[cid];
            if (!active.has(c.id)) {
                if (clients[cid].transceiver) {
                    updateSdp = true;
                    transceiverPool.push(c.transceiver);
                }
                c.ctrBlock.remove();
                delete clients[cid];
            }
        }

        if (rtc.connectionState == 'connected' && updateSdp) {
            updateRtc();
        }
    }

    function updateRtc() {
        return rtc.createOffer({
            offerToReceiveAudio: 1,
            offerToReceiveVideo: 0,
            voiceActivityDetection: false
        })
        .then(offer => {
            let sdp = offer.sdp;

            log('Local SDP:\n' + sdp);
            socket.send(JSON.stringify({
                command: 'offer',
                sdp: sdp
            }));

            return rtc.setLocalDescription({
                type: 'offer',
                sdp: sdp,
            });
        })
        .then(offer => {
            let bundle = rtc.localDescription.sdp.match(/a=group:BUNDLE\s+([^\n]+)/)[1].split(' ');

            let temp = [
                'v=0',
                'o=- 8053710768511283638 2 IN IP4 ' + serverIp,
                's=-',
                't=0 0',
                'a=group:BUNDLE ' + bundle.join(' '),
                'a=msid-semantic: WMS',
                'm=audio ' + serverPort + ' UDP/TLS/RTP/SAVPF 0 8',
                'c=IN IP4 ' + serverIp,
                'a=rtcp:' + serverPort + ' IN IP4 ' + serverIp,
                'a=candidate:1270274445 1 udp 2122260223 ' + serverIp + ' ' + serverPort + ' typ host generation 0',
                'a=ice-lite',
                'a=ice-ufrag:4hYU',
                'a=ice-pwd:AzxUGoufPfAK/IhG6St7bZzU',
                'a=ice-options:trickle',
                'a=fingerprint:sha-256 D2:A9:56:4A:CC:8E:ED:F8:30:F0:AA:82:E7:36:8B:BD:96:9E:1F:51:8A:48:C0:1C:B4:80:A7:50:75:37:7F:16',
                'a=setup:active',
                'a=rtcp-mux',
                'a=mid:0',
                'a=msid:- ' + microphone.id,
                'a=recvonly',
                'a=rtpmap:0 PCMU/8000',
                'a=rtpmap:8 PCMA/8000'
            ];

            for (let mid in bundle) {
                if (mid == 0) { continue; }

                temp = temp.concat([
                    'm=audio ' + serverPort + ' UDP/TLS/RTP/SAVPF 0 8',
                    'c=IN IP4 ' + serverIp,
                    'a=rtcp:' + serverPort + ' IN IP4 ' + serverIp,
                    'a=ice-ufrag:4hYU',
                    'a=ice-pwd:AzxUGoufPfAK/IhG6St7bZzU',
                    'a=ice-options:trickle',
                    'a=fingerprint:sha-256 D2:A9:56:4A:CC:8E:ED:F8:30:F0:AA:82:E7:36:8B:BD:96:9E:1F:51:8A:48:C0:1C:B4:80:A7:50:75:37:7F:16',
                    'a=setup:active',
                    'a=mid:' + mid,
                    'a=rtcp-mux',
                ]);

                let c = null;
                for (let cid in clients) {
                    if (clients[cid].transceiver && clients[cid].transceiver.mid == mid)
                    {
                        c = clients[cid];
                        break;
                    }
                }

                if (c) {
                    temp = temp.concat([
                        'a=sendonly',
                        'a=msid:- ' + c.id,
                        'a=rtpmap:0 PCMU/8000',
                        'a=rtpmap:8 PCMA/8000',
                        'a=ssrc:' + c.id + ' cname:' + c.id,
                        'a=ssrc:' + c.id + ' msid:- ' + c.id,
                        'a=ssrc:' + c.id + ' mslabel:-',
                        'a=ssrc:' + c.id + ' label:' + c.id
                    ]);
                } else {
                    temp = temp.concat([
                        'a=inactive'
                    ]);
                }
            }

            temp.push('');
            let sdp = temp.join('\n');

            log('Remote SDP:\n' + sdp);
            return rtc.setRemoteDescription({
                type: 'answer',
                sdp: sdp,
            });
        });
    }

    function wsInit() {
        socket = new WebSocket('wss://' + document.location.host + '/api');

        socket.onopen = function(ev) {
            log('connection opened');
        };

        socket.onclose = function(ev) {
            log('connection closed');
            rtc.close();
            ctrPtt.disabled = true;
            setTimeout(wsInit, 1000);
        };

        socket.onerror = function(ev) {
            log('connection error');
        };

        socket.onmessage = function(ev) {
            log('received message ' + ev.data);
            let data = JSON.parse(ev.data);
            if (data.command == 'connected') {
                ctrPtt.disabled = false;
                clientId = data.client_id;
                serverIp = data.server_ip;
                serverPort = data.server_port;
                rtcInit();
            } else if (data.command == 'clients') {
                updateClients(data['clients']);
            }
        };
    }

    function rtcInit() {
        rtc = new RTCPeerConnection({
            sdpSemantics: 'unified-plan',
            iceServers: [{
                urls: "stun:" + document.location.host
            }]
        });

        rtc.oniceconnectionstatechange = e => log('ICE state: ' + rtc.iceConnectionState);
        rtc.onsignalingstatechange = e => log('Signalling state: ' + rtc.signalingState);

        navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false
        })
        .then(stream => {
            log('Received local stream');

            var audioTracks = stream.getAudioTracks();
            if (audioTracks.length > 0) {
                log('Using Audio device: ' + audioTracks[0].label);
            }

            microphone = audioTracks[0];
            rtpSender = rtc.addTrack(microphone, stream);
            rtpSender.replaceTrack(null);

            for (let cid in clients) {
                let c = clients[cid];
                if (c.id != clientId && !c.transceiver) {
                    c.transceiver = rtc.addTransceiver('audio', {direction: 'recvonly'});
                }
            }

            return updateRtc();
        })
        .then(() => {
            log('Finalization complete');
        })
        .catch(err => {
            log('catched error on rtc init: ' + err);
        });
    }

    ctrPtt.addEventListener('click', function (ev) {
        ev.preventDefault();
        pttState = !pttState;

        console.log(rtc, rtc.signalingState, rtc.connectionState);
        rtpSender.replaceTrack(pttState ? microphone : null);
        log(pttState ? 'PTT ON' : 'PTT OFF');

        socket.send(JSON.stringify({
            command: 'ptt',
            state: pttState
        }));
    });

    wsInit();
})();
