// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Collections.Concurrent;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    public sealed class DtlsWrapper : IDisposable
    {
        #region Constants

        private const int DTLS_CERT_LIFETIME = 60 * 60 * 24 * 30;

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

        public static string Fingerprint { get; }

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

            _sslCtx = OpenSsl.SSL_CTX_new(OpenSsl.DTLS_method());
            if (_sslCtx == IntPtr.Zero)
                throw new Exception($"Cannot create SSL_CTX: {OpenSsl.GetLastError()}");

            var key = OpenSsl.EVP_PKEY_new();
            if (key == IntPtr.Zero)
                throw new Exception($"Cannot create key: {OpenSsl.GetLastError()}");

            var ecKey = OpenSsl.EC_KEY_new_by_curve_name(OpenSsl.NID_X9_62_prime256v1);
            if (ecKey == IntPtr.Zero)
                throw new Exception($"Cannot create ecKey: {OpenSsl.GetLastError()}");

            if (OpenSsl.EC_KEY_generate_key(ecKey) != 1)
                throw new Exception($"Cannot generate ecKey: {OpenSsl.GetLastError()}");

            if (OpenSsl.EVP_PKEY_assign(key, OpenSsl.NID_X9_62_id_ecPublicKey, ecKey) != 1)
                throw new Exception($"Cannot assign ecKey to key: {OpenSsl.GetLastError()}");

            if (OpenSsl.SSL_CTX_use_PrivateKey(_sslCtx, key) != 1)
                throw new Exception($"Cannot set key to ctx: {OpenSsl.GetLastError()}");

            var x509 = OpenSsl.X509_new();
            if (x509 == IntPtr.Zero)
                throw new Exception($"Cannot create ecKey: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_set_pubkey(x509, key) != 1)
                throw new Exception($"Cannot assign pubkey to x509: {OpenSsl.GetLastError()}");

            var serialNumber = OpenSsl.BN_new();
            if (serialNumber == IntPtr.Zero)
                throw new Exception($"Cannot create BN for serialNumber: {OpenSsl.GetLastError()}");

            if (OpenSsl.BN_pseudo_rand(serialNumber, OpenSsl.SERIAL_RAND_BITS,
                    OpenSsl.BN_RAND_TOP_ANY, OpenSsl.BN_RAND_BOTTOM_ANY) != 1)
                throw new Exception($"Cannot generate random for serialNumber: {OpenSsl.GetLastError()}");

            var serialNumberAddr = OpenSsl.X509_get_serialNumber(x509);
            if (serialNumberAddr == IntPtr.Zero)
                throw new Exception($"Cannot take address for serialNumber: {OpenSsl.GetLastError()}");

            if (OpenSsl.BN_to_ASN1_INTEGER(serialNumber, serialNumberAddr) == IntPtr.Zero)
                throw new Exception($"Cannot assing serialNumber to x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_set_version(x509, 2L) != 1)
                throw new Exception($"Cannot set version to x509: {OpenSsl.GetLastError()}");

            var name = OpenSsl.X509_NAME_new();
            if (name == IntPtr.Zero)
                throw new Exception($"Cannot create name for x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_NAME_add_entry_by_NID(name, OpenSsl.NID_commonName, OpenSsl.MBSTRING_UTF8,
                    Marshal.StringToHGlobalAnsi("WebRTC"), -1, 0, 0) != 1)
                throw new Exception($"Cannot assign name for x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_set_subject_name(x509, name) != 1)
                throw new Exception($"Cannot assign subject name to x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_set_issuer_name(x509, name) != 1)
                throw new Exception($"Cannot assign issuer name to x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_gmtime_adj(OpenSsl.X509_getm_notBefore(x509), 0) == IntPtr.Zero)
                throw new Exception($"Cannot assign issuer notBefore to x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_gmtime_adj(OpenSsl.X509_getm_notAfter(x509), DTLS_CERT_LIFETIME) == IntPtr.Zero)
                throw new Exception($"Cannot assign issuer notAfter to x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.X509_sign(x509, key, OpenSsl.EVP_sha256()) == 0)
                throw new Exception($"Cannot sign x509: {OpenSsl.GetLastError()}");

            if (OpenSsl.SSL_CTX_use_certificate(_sslCtx, x509) != 1)
                throw new Exception($"Cannot set cert to ctx: {OpenSsl.GetLastError()}");

            Fingerprint = GetFingerprint(x509);

            if (OpenSsl.SSL_CTX_set_tlsext_use_srtp(_sslCtx, "SRTP_AES128_CM_SHA1_80") != 0)
                throw new Exception($"Cannot add SRTP extension: {OpenSsl.GetLastError()}");

            // TODO Free mem for unnecessary variables
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

        private static string GetFingerprint(IntPtr x509)
        {
            var bufferHandle = default(GCHandle);
            int length = OpenSsl.EVP_MAX_MD_SIZE;
            var buffer = new byte[length];

            try
            {
                bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                if (OpenSsl.X509_digest(x509, OpenSsl.EVP_sha256(), bufferHandle.AddrOfPinnedObject(), ref length) != 1)
                    throw new Exception($"Cannot calculate digest: {OpenSsl.GetLastError()}");
            }
            finally
            {
                bufferHandle.Free();
            }

            var sb = new StringBuilder("sha-256 ");
            for (var i = 0; i < length; ++i)
                sb.AppendFormat("{0:X2}:", buffer[i]);
            sb.Length -= 1;

            return sb.ToString();
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