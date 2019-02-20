// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.RegularExpressions;

    using WebSocketSharp;
    using WebSocketSharp.Net;

    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Authentication;

    using WebSocketSharp.Server;

    public class Server : IDisposable
    {
        #region Constants

        private const string STATIC_PATH = "PttOnWebRtc.Resources.";

        private const string DEFAULT_FILE = "index.html";

        #endregion Constants

        #region Fields

        private static Dictionary<string, FileCacheInfo> _fileCache;

        private List<string> _namesPool;

        private readonly HttpServer _httpServer;

        private readonly UdpServer _stunServer;

        private readonly UdpServer _rtpServer;

        private FileStream _debugFile;

        private uint _ssrcCounter;

        #endregion Fields

        #region Properties

        public List<Client> Clients { get; }

        public string IceUfrag { get; }

        public string IcePassword { get; }

        public byte[] IcePasswordBytes { get; }

        #endregion Properties

        #region Constructors

        public Server()
        {
            Clients = new List<Client>();
            IceUfrag = GenerateIceFragments(4);
            IcePassword = GenerateIceFragments(22);
            IcePasswordBytes = Encoding.UTF8.GetBytes(IcePassword);

            _namesPool = new List<string> { "Alice", "Bob", "Charlotte", "David", "Emily", "Fargo" };
            _fileCache = new Dictionary<string, FileCacheInfo>();
            _ssrcCounter = 0x10000001;

            _httpServer = new HttpServer(443, true);
            _httpServer.SslConfiguration = new ServerSslConfiguration(
                new X509Certificate2(Resources.ReadFile("PttOnWebRtc.Resources.cert.pfx"), "dev-certificate"))
            {
                EnabledSslProtocols = SslProtocols.Tls12,
            };
            _httpServer.OnGet += HandleGetRequest;
            _httpServer.AddWebSocketService("/api", () => new Client(this));

            _stunServer = new UdpServer(3478);
            _stunServer.OnReceive += HandleStunRequest;

            _rtpServer = new UdpServer(18500);
            _rtpServer.OnReceive += HandleRtpPacket;

            _debugFile = File.Create("debug.g711");

            PrepareStatic();
        }

        #endregion Constructors

        #region Methods

        public void Start()
        {
            _httpServer.Start();
            _stunServer.Start();
            _rtpServer.Start();
        }

        public void Dispose()
        {
            _rtpServer.Stop();
            _stunServer.Stop();
            _httpServer.Stop();
        }

        public void AddClient(Client client, out string name, out uint clientId)
        {
            if (_namesPool.Count == 0)
                throw new Exception("All slots busy");

            name = _namesPool[0];
            _namesPool.RemoveAt(0);
            clientId = _ssrcCounter++;
            client.SetDtlsWrapper(new DtlsWrapper(client, SendCallback));

            Clients.Add(client);
        }

        public void RemoveClient(Client client)
        {
            _namesPool.Add(client.Name);
            Clients.Remove(client);
        }

        public void BroadcastState()
        {
            foreach (var client in Clients)
                client.BroadcastState();
        }

        public void HandleOffer(Client source, string sdp)
        {
            var ufrag = Regex.Match(sdp, @"a=ice-ufrag:\s*(\S+)").Groups[1].Value;
            var pwd = Regex.Match(sdp, @"a=ice-pwd:\s*(\S+)").Groups[1].Value;
            source.SetIceParam(ufrag, pwd);
        }

        private void HandleGetRequest(object sender, HttpRequestEventArgs e)
        {
            var path = e.Request.Url.LocalPath;
            if (!_fileCache.TryGetValue(path, out var content))
            {
                e.Response.StatusCode = 404;
                return;
            }

            if (content.Encoding != null)
                e.Response.ContentEncoding = content.Encoding;
            if (content.ContentType != null)
                e.Response.ContentType = content.ContentType;
            e.Response.WriteContent(content.Data);
        }

        private void HandleStunRequest(IPEndPoint from, byte[] data)
        {
            try
            {
                if (StunPacket.TryParse(data, out var packet) != StunPacket.ResultCodes.Ok)
                    return;

                if (packet.MessageType != StunPacket.MessageTypes.BindingRequest || packet.MessageIntegrity != null)
                    return;

                var answer = new StunPacket
                {
                    MessageType = StunPacket.MessageTypes.BindingSuccessResponse,
                    TransactionId = packet.TransactionId,
                    XorMappedAddress = from,
                    Fingerprint = true,
                };

                _stunServer.Send(from, answer.Pack());
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private void HandleRtpPacket(IPEndPoint from, byte[] data)
        {
            try
            {
                var client = FindClient(from);

                if (client != null &&
                    client.SrtpContext.TryParseSrtpPacket(data, out var rtp) == RtpPacket.ResultCodes.Ok)
                {
                    _debugFile.Write(rtp.Payload, 0, rtp.Payload.Length);

                    foreach (var another in Clients)
                    {
                        IPEndPoint remoteEp;
                        byte[] packet;

                        rtp.Ssrc = client.ClientId;

                        if (client == another) continue;
                        if ((remoteEp = another.RemoteRtp) == null) continue;
                        if ((packet = another.SrtpContext.PackSrtpPacket(rtp)) == null) continue;

                        _rtpServer.Send(remoteEp, packet);
                    }
                }
                else if (StunPacket.TryParse(data, out var stun) == StunPacket.ResultCodes.Ok)
                {
                    if (stun.MessageType != StunPacket.MessageTypes.BindingRequest)
                        return;

                    client = FindClientAndCheckIntegrity(stun);
                    if (client == null)
                    {
                        Console.Error.WriteLineAsync($"Cannot found client with username {stun.Username}");
                        // TODO implement error
                        //var answer = new StunPacket
                        //{
                        //    MessageType = StunPacket.MessageTypes.BindingSuccessResponse,
                        //    TransactionId = packet.TransactionId,
                        //    Fingerprint = true,
                        //};

                        //_rtpServer.Send(from, answer.Pack());
                        return;
                    }

                    var answer = new StunPacket
                    {
                        MessageType = StunPacket.MessageTypes.BindingSuccessResponse,
                        TransactionId = stun.TransactionId,
                        XorMappedAddress = from,
                        MessageIntegrityKey = IcePasswordBytes,
                        Fingerprint = true,
                    };

                    client.SetRtpParam(from);
                    _rtpServer.Send(from, answer.Pack());
                    client.Dtls.DoHandshake(() => client.SrtpContext.SetMasterKeys(client.Dtls.Ssl, true));
                }
                else if (DtlsPacket.CheckPacket(data, 0) == DtlsPacket.ResultCodes.Ok)
                {
                    if (client == null)
                    {
                        Console.Error.WriteLineAsync($"Cannot found client with ip {from}");
                        return;
                    }
                    client.Dtls.Add(data);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private void SendCallback(Client client, byte[] data)
        {
            _rtpServer.Send(client.RemoteRtp, data);
        }

        private Client FindClient(IPEndPoint from)
        {
            return Clients.Find(x => from.Equals(x.RemoteRtp));
        }

        private Client FindClientAndCheckIntegrity(StunPacket packet)
        {
            if (packet.MessageIntegrity == null || packet.Username == null)
                return null;

            var client = Clients.Find(a => a.Ufrag == packet.Username.Split(':')[1]);
            if (client == null)
                return null;

            if (!packet.VerifyIntegrity(IcePasswordBytes))
                return null;

            return client;
        }

        private void PrepareStatic()
        {
            foreach (var filename in Resources.Enumerate(STATIC_PATH))
            {
                Encoding encoding = null;
                string contentType = null;

                if (filename.EndsWith(".html")) {
                    encoding = Encoding.UTF8;
                    contentType = "text/html";
                }
                else if (filename.EndsWith(".js"))
                {
                    encoding = Encoding.UTF8;
                    contentType = "application/javascript";
                }
                else if (filename.EndsWith(".css"))
                {
                    encoding = Encoding.UTF8;
                    contentType = "text/css";
                }
                else
                {
                    continue;
                }

                var path = '/' + filename.Substring(STATIC_PATH.Length);
                var data = Resources.ReadFile(filename);
                var fileCacheInfo = new FileCacheInfo(data, encoding, contentType);
                _fileCache[path] = fileCacheInfo;
                if (filename.EndsWith(DEFAULT_FILE))
                    _fileCache[path.Substring(0, path.Length - DEFAULT_FILE.Length)] = fileCacheInfo;
            }
        }

        private string GenerateIceFragments(int length)
        {
            const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var r = new Random();

            var s = new char[length];
            for (var i = 0; i < length; ++i)
                s[i] = ALPHABET[r.Next(ALPHABET.Length)];

            return new string(s);
        }

        #endregion Methods

        #region Classes

        private class FileCacheInfo
        {
            public byte[] Data { get; }

            public Encoding Encoding { get; }

            public string ContentType { get; }

            public FileCacheInfo(byte[] data, Encoding encoding, string contentType)
            {
                Data = data;
                Encoding = encoding;
                ContentType = contentType;
            }
        }

        #endregion Classes
    }
}