// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;

    public class UdpServer
    {
        private const int BUFFER_SIZE = 2048;

        private readonly ushort _port;
        private readonly SocketAsyncEventArgs _receiveArgs;
        private readonly SocketAsyncEventArgs _sendArgs;
        private readonly AutoResetEvent _sendSyncEvent;
        private Socket _socket;

        public event Action<IPEndPoint, byte[]> OnReceive;

        public UdpServer(ushort port)
        {
            _port = port;
            _receiveArgs = new SocketAsyncEventArgs();
            _receiveArgs.Completed += HandleReceive;
            _receiveArgs.SetBuffer(new byte[BUFFER_SIZE], 0, BUFFER_SIZE);
            _sendArgs = new SocketAsyncEventArgs();
            _sendArgs.Completed += HandleSend;
            _sendSyncEvent = new AutoResetEvent(true);
        }

        public void Start()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(IPAddress.Any, _port));
            ReceiveFrom();
        }

        public void Stop()
        {
            _socket.Close();
        }

        public void Send(IPEndPoint to, byte[] data)
        {
            _sendSyncEvent.WaitOne();
            _sendArgs.SetBuffer(data, 0, data.Length);
            _sendArgs.RemoteEndPoint = to;
            _socket.SendToAsync(_sendArgs);
        }

        private void ReceiveFrom()
        {
            _receiveArgs.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            _socket.ReceiveFromAsync(_receiveArgs);
        }

        private void HandleReceive(object sender, SocketAsyncEventArgs e)
        {
            // TODO implement queue
            var temp = new byte[e.BytesTransferred];
            Array.Copy(_receiveArgs.Buffer, 0, temp, 0, _receiveArgs.BytesTransferred);
            OnReceive?.Invoke((IPEndPoint)_receiveArgs.RemoteEndPoint, temp);
            ReceiveFrom();
        }

        private void HandleSend(object sender, SocketAsyncEventArgs e)
        {
            // TODO implement queue
            _sendSyncEvent.Set();
        }
    }
}