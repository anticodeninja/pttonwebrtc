// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Collections.Concurrent;
    using System.Linq;
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

        public uint ClientId { get; set; }

        public string Name { get; private set; }

        public string Ufrag { get; private set; }

        public byte[] Pwd { get; private set; }

        public bool PttState { get; private set; }

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

        public void BroadcastState()
        {
            Send(
                new JObject {
                    ["command"] = "clients",
                    ["clients"] = new JArray(Server.Clients.Select(c => new JObject
                    {
                        ["id"] = c.ClientId,
                        ["name"] = c.Name,
                        ["state"] = c.PttState ? "active" : "idle",
                    }).ToArray()),
                }.ToString()
            );
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

            try
            {
                Server.AddClient(this, out var name, out var clientId);
                ClientId = clientId;
                Name = name;
                Send(
                    new JObject{
                        ["command"] = "connected",
                        ["name"] = Name,
                        ["client_id"] = clientId,
                        ["server_ip"] = Context.ServerEndPoint.Address.ToString(),
                        ["server_port"] = 18500, // TODO Unmagic
                    }.ToString()
                );
                Server.BroadcastState();
            }
            catch (Exception e)
            {
                Send(
                    new JObject{
                        ["command"] = "disconnected",
                        ["reason"] = e.Message,
                    }.ToString()
                );
                Context.WebSocket.Close();
            }
        }

        protected override void OnClose(CloseEventArgs e)
        {
            Server.RemoveClient(this);
            Server.BroadcastState();
            base.OnClose(e);
        }

        protected override void OnMessage(MessageEventArgs e)
        {
            var json = JObject.Parse(e.Data);
            switch (json["command"].Value<string>())
            {
                case "ptt":
                    PttState = json["state"].Value<bool>();
                    Server.BroadcastState();
                    break;
                case "offer":
                    Server.HandleOffer(this, json["sdp"].Value<string>());
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