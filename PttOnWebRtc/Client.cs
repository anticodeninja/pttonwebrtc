// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System;
    using System.Collections.Concurrent;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    using Newtonsoft.Json.Linq;
    using WebSocketSharp;
    using WebSocketSharp.Server;

    public class Client : WebSocketBehavior
    {
        private readonly GCHandle _handle;

        private int _connectionState;

        public Server Server { get; }

        public SrtpContext SrtpContext { get; }

        public string Name { get; private set; }

        public string Ufrag { get; private set; }

        public byte[] Pwd { get; private set; }

        public IPEndPoint RemoteRtp { get; private set; }

        public IntPtr Ssl { get; private set; }

        public IntPtr Bio { get; private set; }

        public IntPtr Handle => GCHandle.ToIntPtr(_handle);

        public BlockingCollection<byte[]> DtlsQueue { get; }

        public Client(Server server)
        {
            Server = server;
            DtlsQueue = new BlockingCollection<byte[]>();
            SrtpContext = new SrtpContext();
            _handle = GCHandle.Alloc(this);
        }

        public static Client FromHandle(IntPtr ptr)
        {
            return (Client)GCHandle.FromIntPtr(ptr).Target;
        }

        public void HandlePtt(Client source, bool value)
        {
            Send($"{{command:\"ptt_event\",state:{value},source:\"{source.Name}\"}}");
        }

        public void SetIceParam(string ufrag, string pwd)
        {
            Ufrag = ufrag;
            Pwd = Encoding.UTF8.GetBytes(pwd);
        }

        public IntPtr SetBio(IntPtr bio) => Bio = bio;
        public void SetSsl(IntPtr ssl) => Ssl = ssl;
        public void SetRtpParam(IPEndPoint remoteRtp) => RemoteRtp = remoteRtp;

        protected override void OnOpen()
        {
            base.OnOpen();

            Name = Server.AddClient(this);
            if (Name != null)
            {
                Send($"{{command:\"connected\",name:\"{Name}\"}}");
            }
            else
            {
                Send($"{{command:\"disconnected\",reason:\"all slots are busy\"}}");
                Context.WebSocket.Close();
            }
        }

        protected override void OnClose(CloseEventArgs e)
        {
            Server.RemoveClient(this);
            base.OnClose(e);
        }

        protected override void OnMessage(MessageEventArgs e)
        {
            var json = JObject.Parse(e.Data);
            switch (json["command"].Value<string>())
            {
                case "ptt":
                    Server.HandlePtt(this, json["state"].Value<bool>());
                    break;
                case "offer":
                    Server.HandleOffer(this, json["offer"]["sdp"].Value<string>());
                    break;
            }
        }

        public bool SetConnectState()
        {
            return Interlocked.CompareExchange(ref _connectionState, 1, 0) == 0;
        }

        public void ClearConnectState()
        {
            Interlocked.Exchange(ref _connectionState, 0);
        }
    }
}