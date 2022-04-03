using Chaos.NaCl;

namespace dotnetstandard_bip32
{
    public class Key 
    {
        readonly byte[] _privateKey;
        public byte[] PrivateKey => _privateKey;

        public byte[] PublicKey => GetPublicKey();

        public Key(byte[] key)
        {
            _privateKey = key;
        }

        public byte[] GetPublicKey(bool withZeroByte = true)
        {
            Ed25519.KeyPairFromSeed(out var publicKey, out _, _privateKey);

            var zero = new byte[] { 0 };

            var buffer = new BigEndianBuffer();
            if (withZeroByte)
                buffer.Write(zero);

            buffer.Write(publicKey);

            return buffer.ToArray();
        }

        public byte[] GetExpandedPrivateKey()
        {
            Ed25519.KeyPairFromSeed(out _, out var expandedPrivateKey, _privateKey);

            var buffer = new BigEndianBuffer();

            buffer.Write(expandedPrivateKey);
            return buffer.ToArray();
        }
    }
}