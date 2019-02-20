// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Collections.Concurrent;
    using System.Runtime.InteropServices;
    using System.Threading;

    public sealed class DtlsWrapper : IDisposable
    {
        #region Constants

        private const int DTLS_TIMEOUT = 3000;

        #endregion Constants

        #region Fields

        private static readonly IntPtr _bioMeth;

        private static readonly IntPtr _sslCtx;

        private static readonly OpenSsl.WriteCb _bioWrite;

        private static readonly OpenSsl.ReadCb _bioRead;

        private static readonly OpenSsl.CtrlCb _bioCtrl;

        private readonly Client _client;

        private readonly Action<Client, byte[]> _sendCallback;

        private readonly IntPtr _bio;

        private readonly IntPtr _ssl;

        private readonly BlockingCollection<byte[]> _packets;

        private readonly GCHandle _handle;

        private int _connectionState;

        #endregion Fields

        #region Properties

        public IntPtr Ssl => _ssl;

        #endregion Properties

        #region Constructors

        static DtlsWrapper()
        {
            _bioMeth = OpenSsl.BIO_meth_new(1, "dtls-wrapper");

            _bioWrite = BioWrite;
            _bioRead = BioRead;
            _bioCtrl = BioCtrl;

            if (_bioMeth == IntPtr.Zero)
                throw new Exception($"Cannot initialize bioMeth: {OpenSsl.GetLastError()}");
            if (OpenSsl.BIO_meth_set_write(_bioMeth, _bioWrite) != 1)
                throw new Exception($"Cannot initialize bioMethWrite: {OpenSsl.GetLastError()}");
            if (OpenSsl.BIO_meth_set_read(_bioMeth, _bioRead) != 1)
                throw new Exception($"Cannot initialize bioMethRead: {OpenSsl.GetLastError()}");
            if (OpenSsl.BIO_meth_set_ctrl(_bioMeth, _bioCtrl) != 1)
                throw new Exception($"Cannot initialize bioMethCtrl: {OpenSsl.GetLastError()}");

            var certBio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            if (certBio == IntPtr.Zero)
                throw new Exception($"Cannot allocate cert BIO: {OpenSsl.GetLastError()}");

            // TODO generate temporary certificates
            var certData = Resources.ReadFile("PttOnWebRtc.Resources.p2.pem");
            if (OpenSsl.BIO_write(certBio, certData, certData.Length) != certData.Length)
                throw new Exception($"Cannot initialize cert BIO: {OpenSsl.GetLastError()}");

            _sslCtx = OpenSsl.SSL_CTX_new(OpenSsl.DTLS_method());
            if (_sslCtx == IntPtr.Zero)
                throw new Exception($"Cannot create SSL_CTX: {OpenSsl.GetLastError()}");

            var cert = OpenSsl.PEM_read_bio_X509(certBio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (cert == IntPtr.Zero)
                throw new Exception($"Cannot initialize cert: {OpenSsl.GetLastError()}");

            if (OpenSsl.SSL_CTX_use_certificate(_sslCtx, cert) != 1)
                throw new Exception($"Cannot set cert to ctx: {OpenSsl.GetLastError()}");

            var keyBio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            if (keyBio == IntPtr.Zero)
                throw new Exception($"Cannot allocate key BIO: {OpenSsl.GetLastError()}");

            var keyData = Resources.ReadFile("PttOnWebRtc.Resources.p2.key");
            if (OpenSsl.BIO_write(keyBio, keyData, keyData.Length) != keyData.Length)
                throw new Exception($"Cannot initialize key BIO: {OpenSsl.GetLastError()}");

            var key = OpenSsl.PEM_read_bio_PrivateKey(keyBio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (key == IntPtr.Zero)
                throw new Exception($"Cannot initialize key: {OpenSsl.GetLastError()}");

            if (OpenSsl.SSL_CTX_use_PrivateKey(_sslCtx, key) != 1)
                throw new Exception($"Cannot set key to ctx: {OpenSsl.GetLastError()}");

            if (OpenSsl.SSL_CTX_set_tlsext_use_srtp(_sslCtx, "SRTP_AES128_CM_SHA1_80") != 0)
                throw new Exception($"Cannot add SRTP extension: {OpenSsl.GetLastError()}");
        }

        public DtlsWrapper(Client client, Action<Client, byte[]> sendCallback)
        {
            _client = client;
            _sendCallback = sendCallback;

            _bio = OpenSsl.BIO_new(_bioMeth);
            if (_bio == IntPtr.Zero)
                throw new Exception("Cannot allocate exchange BIO");

            _ssl = OpenSsl.SSL_new(_sslCtx);
            if (_ssl == IntPtr.Zero)
            {
                OpenSsl.BIO_free(_bio);
                throw new Exception("Cannot initialize ssl");
            }

            OpenSsl.SSL_set_bio(Ssl, _bio, _bio);

            _handle = GCHandle.Alloc(this, GCHandleType.Normal);
            OpenSsl.BIO_set_data(_bio, GCHandle.ToIntPtr(_handle));
            _packets = new BlockingCollection<byte[]>();
        }

        ~DtlsWrapper() => Dispose(false);

        #endregion Constructors

        #region Methods

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Add(byte[] data) => _packets.Add(data);

        public void DoHandshake(Action callback)
        {
            if (Interlocked.CompareExchange(ref _connectionState, 1, 0) == 0)
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    while (_packets.TryTake(out var _)) {}

                    OpenSsl.SSL_set_connect_state(Ssl);
                    if (OpenSsl.SSL_do_handshake(Ssl) != 1)
                    {
                        Console.WriteLine($"Cannot establish DTLS: {OpenSsl.GetLastError()}");
                        Interlocked.Exchange(ref _connectionState, 0);
                        return;
                    }

                    callback();
                });
            }
        }

        private static int BioWrite(IntPtr bio, IntPtr data, int dlen)
        {
            var wrapper = (DtlsWrapper)GCHandle.FromIntPtr(OpenSsl.BIO_get_data(bio)).Target;

            var temp = new byte[dlen];
            Marshal.Copy(data, temp, 0, dlen);
            wrapper._sendCallback(wrapper._client, temp);

            return dlen;
        }

        private static int BioRead(IntPtr bio, IntPtr data, int dlen)
        {
            var wrapper = (DtlsWrapper)GCHandle.FromIntPtr(OpenSsl.BIO_get_data(bio)).Target;
            if (!wrapper._packets.TryTake(out var packet, DTLS_TIMEOUT))
                return 0;

            Marshal.Copy(packet, 0, data, packet.Length);
            return packet.Length;
        }

        private static long BioCtrl(IntPtr bio, int cmd, long larg, IntPtr parg)
        {
            // bss_dgram.c was used as reference
            switch ((OpenSsl.BioCtrls)cmd)
            {
                case OpenSsl.BioCtrls.Push:
                    return -1;
                case OpenSsl.BioCtrls.Flush:
                    return 1;
                case OpenSsl.BioCtrls.WPending:
                    return 0;
                case OpenSsl.BioCtrls.DgramQueryMtu:
                    return 1450;
                case OpenSsl.BioCtrls.DgramSetMtu:
                    return larg;
                case OpenSsl.BioCtrls.DgramSetNextTimeout:
                    return 1;
                case OpenSsl.BioCtrls.DgramGetMtuOverhead:
                    return 28; // IPv4 + UDP
            }
            return 0;
        }

        private void Dispose(bool disposing)
        {
            if (_handle.IsAllocated)
                _handle.Free();
            if (_ssl != IntPtr.Zero)
                OpenSsl.SSL_free(_ssl); // SSL_free also free _bio
            if (disposing)
                _packets?.Dispose();
        }

        #endregion Methods
    }
}