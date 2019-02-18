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
        clients = [],
        clientId = 0,
        serverIp = '127.0.0.1',
        serverPort = 18500,
        rtpSender,
        rtc,
        rtcLocalStream;

    function log(value) {
        ctrDebugLog.value += value + '\n';
        ctrDebugLog.scrollTop = ctrDebugLog.scrollHeight
    }

    function updateClients() {
        let active = new Set();
        let updateSdp = false;

        for (let i = 0, len = clients.length; i < len; ++i) {
            let c = clients[i];
            let blockId = 'c-' + c.id;
            active.add(blockId);
            let ctrClient = ctrClients.querySelector('.' + blockId);
            if (!ctrClient) {
                updateSdp = true;
                ctrClient = document.createElement('div');
                ctrClient.className = blockId;
                ctrClient.innerHTML = '<span class="name"></span>' +
                                      '<span class="state"></span>' +
                                      '<audio autoplay controls></audio>';
                ctrClients.appendChild(ctrClient);
            }
            ctrClient.querySelector('.name').innerText = c.name;
            ctrClient.querySelector('.state').innerText = c.state + (c.id == clientId ? ' (me)' : '');
        }

        for (let i = 0; i < ctrClients.children.length;) {
            if (!active.has(ctrClients.children[i].className)) {
                updateSdp = true;
                ctrClients.children[i].remove();
            } else {
                i += 1;
            }
        }

        if (updateSdp) {
            updateRtc();
        }
    }

    function gotRemoteStream(e) {
        let ctrAudio = ctrClients.querySelector('.c-' + e.track.id + ' audio');
        if (ctrAudio.srcObject !== e.streams[0]) {
            ctrAudio.srcObject = e.streams[0];
            log('Received remote stream');
        }
    }

    function updateRtc() {
        return rtc.createOffer({
            offerToReceiveAudio: 1,
            offerToReceiveVideo: 0,
            voiceActivityDetection: false
        })
        .then(offer => {
            let sdp = offer.sdp.replace(/ssrc:\d+/g, 'ssrc:' + clientId);
            log('Local SDP:\n' + offer.sdp);
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
            let temp = [
                'v=0',
                'o=- 8053710768511283638 2 IN IP4 ' + serverIp,
                's=-',
                't=0 0',
                'a=group:BUNDLE audio',
                'a=msid-semantic: WMS',
                'm=audio ' + serverPort + ' UDP/TLS/RTP/SAVPF 0 8',
                'c=IN IP4 ' + serverIp,
                'a=candidate:1270274445 1 udp 2122260223 ' + serverIp + ' ' + serverPort + ' typ host generation 0',
                'a=ice-lite',
                'a=ice-ufrag:4hYU',
                'a=ice-pwd:AzxUGoufPfAK/IhG6St7bZzU',
                'a=ice-options:trickle',
                'a=fingerprint:sha-256 D2:A9:56:4A:CC:8E:ED:F8:30:F0:AA:82:E7:36:8B:BD:96:9E:1F:51:8A:48:C0:1C:B4:80:A7:50:75:37:7F:16',
                'a=setup:active',
                'a=rtcp-mux',
                'a=mid:audio',
                'a=sendrecv',
                'a=rtpmap:0 PCMU/8000',
                'a=rtpmap:8 PCMA/8000'
            ];

            for (let i = 0, len = clients.length; i < len; ++i) {
                let c = clients[i];
                if (c.id == clientId) { continue; }
                temp.push('a=ssrc:' + c.id + ' cname:' + c.id);
                temp.push('a=ssrc:' + c.id + ' msid:' + c.id + ' ' + c.id);
                temp.push('a=ssrc:' + c.id + ' mslabel:' + c.id);
                temp.push('a=ssrc:' + c.id + ' label:' + c.id);
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
                clients = data['clients'];
                updateClients();
            }
        };
    }

    function rtcInit() {
        rtc = new RTCPeerConnection({
            iceServers: [{
                urls: "stun:" + document.location.host
            }]
        });
        rtc.ontrack = gotRemoteStream;
        rtc.oniceconnectionstatechange = e => log('ICE state: ' + rtc.iceConnectionState);
        rtc.onsignalingstatechange = e => log('Signalling state: ' + rtc.signalingState);

        navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false
        })
        .then(stream => {
            rtcLocalStream = stream;

            log('Received local stream');

            var audioTracks = rtcLocalStream.getAudioTracks();
            if (audioTracks.length > 0) {
                log('Using Audio device: ' + audioTracks[0].label);
            }

            microphone = rtcLocalStream.getTracks()[0];

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

        if (pttState) {
            rtpSender = rtc.addTrack(microphone, rtcLocalStream);
        } else {
            rtc.removeTrack(rtpSender);
        }

        updateRtc();
        log(pttState ? 'PTT ON' : 'PTT OFF');

        socket.send(JSON.stringify({
            command: 'ptt',
            state: pttState
        }));
    });

    wsInit();
})();
