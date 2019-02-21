// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Text;

    using Newtonsoft.Json.Linq;
    using WebSocketSharp;
    using WebSocketSharp.Server;

    public class Client : WebSocketBehavior
    {
        #region Fields

        private uint _clientId;

        private string _name;

        #endregion Fields

        #region Properties

        public Server Server { get; }

        public uint ClientId => _clientId;

        public string Name => _name;

        public SrtpContext SrtpContext { get; private set; }

        public DtlsWrapper Dtls { get; private set; }

        public string Ufrag { get; private set; }

        public byte[] Pwd { get; private set; }

        public bool PttState { get; private set; }

        public IPEndPoint RemoteRtp { get; private set; }

        #endregion Properties

        #region Constructors

        public Client(Server server)
        {
            Server = server;
            SrtpContext = new SrtpContext();
        }

        #endregion Constructors

        #region Methods

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

        public void SetDtlsWrapper(DtlsWrapper dtls) => Dtls = dtls;
        public void SetRtpParam(IPEndPoint remoteRtp) => RemoteRtp = remoteRtp;

        protected override void OnOpen()
        {
            base.OnOpen();

            try
            {
                Server.AddClient(this, out _name, out _clientId);
                Send(
                    new JObject{
                        ["command"] = "connected",
                        ["name"] = Name,
                        ["client_id"] = ClientId,
                        ["server_ufrag"] = Server.IceUfrag,
                        ["server_password"] = Server.IcePassword,
                        ["server_fingerprint"] = DtlsWrapper.Fingerprint,
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

            SrtpContext?.Dispose();
            SrtpContext = null;

            Dtls?.Dispose();
            Dtls = null;

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

        #endregion Methods
    }
}