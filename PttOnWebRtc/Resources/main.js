// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

(function (){
    'use strict';

    let pttState = false,
        ctrDebugLog,
        ctrPtt,
        socket,
        rtc,
        rtcLocalStream;

    function init() {
        ctrDebugLog = document.getElementById('debug-log');
        ctrPtt = document.getElementById('ptt');

        ctrDebugLog.value += 'Initialized\n';

        ctrPtt.addEventListener('click', function (ev) {
            ev.preventDefault();
            pttState = !pttState;
            ctrDebugLog.value += pttState ? 'PTT ON\n' : 'PTT OFF\n';

            socket.send(JSON.stringify({
                command: 'ptt',
                state: pttState
            }));
        });

        wsInit();
    }

    function wsInit() {
        socket = new WebSocket('wss://' + document.location.host + '/api');
        ctrPtt.disabled = true;

        socket.onopen = function(ev) {
            ctrDebugLog.value += 'connection opened\n';
            rtcInit();
            ctrPtt.disabled = false;
        };

        socket.onclose = function(ev) {
            ctrDebugLog.value += 'connection closed\n';
            setTimeout(wsInit, 1000);
        };

        socket.onerror = function(ev) {
            ctrDebugLog.value += 'connection error\n';
        };

        socket.onmessage = function(ev) {
            ctrDebugLog.value += 'received message ' + ev.data + '\n';
        };
    }

    function rtcInit() {
        rtc = new RTCPeerConnection({
            iceServers: [{
                urls: "stun:" + document.location.host
            }]
        });
        rtc.oniceconnectionstatechange = e => ctrDebugLog.value += 'ICE state: ' + rtc.iceConnectionState + '\n';
        rtc.onsignalingstatechange = e => ctrDebugLog.value += 'Signalling state: ' + rtc.signalingState + '\n';

        navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false
        })
        .then(stream => {
            rtcLocalStream = stream;

            ctrDebugLog.value += 'Received local stream\n';

            var audioTracks = rtcLocalStream.getAudioTracks();
            if (audioTracks.length > 0) {
                ctrDebugLog.value += 'Using Audio device: ' + audioTracks[0].label + '\n';
            }

            rtcLocalStream.getTracks().forEach(track => {
                rtc.addTrack(
                    track,
                    rtcLocalStream
                );
            });

            return rtc.createOffer({
                offerToReceiveAudio: 1,
                offerToReceiveVideo: 0,
                voiceActivityDetection: false
            });
        })
        .then(offer => {
            ctrDebugLog.value += 'Created offer:\n' + offer.sdp + '\n';
            socket.send(JSON.stringify({
                command: 'offer',
                offer: offer
            }));
            return rtc.setLocalDescription(offer);
        })
        .then(offer => {
            let remoteSdp =
                'v=0\n' +
                'o=- 8053710768511283638 2 IN IP4 192.168.1.240\n' +
                's=-\n' +
                't=0 0\n' +
                'a=group:BUNDLE audio\n' +
                'a=msid-semantic: WMS\n' +
                'm=audio 18500 UDP/TLS/RTP/SAVPF 0 8\n' +
                'c=IN IP4 192.168.1.240\n' +
                'a=candidate:1270274445 1 udp 2122260223 192.168.1.240 18500 typ host generation 0\n' +
                'a=ice-lite\n' +
                'a=ice-ufrag:4hYU\n' +
                'a=ice-pwd:AzxUGoufPfAK/IhG6St7bZzU\n' +
                'a=ice-options:trickle\n' +
                'a=fingerprint:sha-256 D2:A9:56:4A:CC:8E:ED:F8:30:F0:AA:82:E7:36:8B:BD:96:9E:1F:51:8A:48:C0:1C:B4:80:A7:50:75:37:7F:16\n' +
                'a=setup:active\n' +
                'a=rtcp-mux\n' +
                'a=mid:audio\n' +
                'a=recvonly\n' +
                'a=rtpmap:0 PCMU/8000\n' +
                'a=rtpmap:8 PCMA/8000\n';
            ctrDebugLog.value += 'Try to set remote SDP:\n' + remoteSdp + '\n';
            return rtc.setRemoteDescription({
                type: 'answer',
                sdp: remoteSdp
            });
        })
        //.then(() => {
        //    ctrDebugLog.value += 'Setted remote description\n';

        //    return rtc.addIceCandidate({
        //        candidate: "candidate:1270274445 1 udp 2122260223 192.168.1.4 18500 typ host generation 0 ufrag 4hYU network-id 1",
        //        sdpMLineIndex: 0,
        //        sdpMid: "audio"
        //    });
        //})
        //.then(() => {
        //    ctrDebugLog.value += 'Setted ICE candidate\n';
        //    return rtc.addIceCandidate(null);
        //})
        .then(() => {
            ctrDebugLog.value += 'Finalization complete\n';
        })
        .catch(err => {
            ctrDebugLog.value += 'catched error on rtc init: ' + err + '\n';
        });
    }

    (window || global).init = init;
})();