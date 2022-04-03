using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace dotnetstandard_bip32
{
    public class ExtKey
    {
        public byte[] ChainCode { get; private set; }
        public Key Key { get; private set; }

        public ExtKey(string seed)
        {
            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);
            
            Key = new Key(masterKeyFromSeed.Key);
            ChainCode = masterKeyFromSeed.ChainCode;
        }

        public ExtKey(byte[] key, byte[] chainCode)
        {
            Key = new Key(key);
            ChainCode = chainCode;
        }

        readonly string curve = "ed25519 seed";
        readonly uint hardenedOffset = 0x80000000;

        private (byte[] Key, byte[] ChainCode) GetMasterKeyFromSeed(string seed)
        {
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Encoding.UTF8.GetBytes(curve)))
            {
                var i = hmacSha512.ComputeHash(seed.HexToByteArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                return (Key: il, ChainCode: ir);
            }
        }

        private (byte[] Key, byte[] ChainCode) GetChildKeyDerivation(byte[] key, byte[] chainCode, uint index)
        {
            BigEndianBuffer buffer = new BigEndianBuffer();

            buffer.Write(new byte[] { 0 });
            buffer.Write(key);
            buffer.WriteUInt(index);

            using (HMACSHA512 hmacSha512 = new HMACSHA512(chainCode))
            {
                var i = hmacSha512.ComputeHash(buffer.ToArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                return (Key: il, ChainCode: ir);
            }
        }

        private bool IsValidPath(string path)
        {
            var regex = new Regex("^m(\\/[0-9]+')+$");

            if (!regex.IsMatch(path))
                return false;

            var valid = !(path.Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Any(a => !Int32.TryParse(a, out _)));

            return valid;
        }


        public ExtKey DerivePath(string path)
        {
            if (!IsValidPath(path))
                throw new FormatException("Invalid derivation path");

            var masterKeyFromSeed = (Key: this.Key.PrivateKey, this.ChainCode);

            var segments = path
                .Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Select(a => Convert.ToUInt32(a, 10));

            var results = segments
                .Aggregate(masterKeyFromSeed, (mks, next) => GetChildKeyDerivation(mks.Key, mks.ChainCode, next + hardenedOffset));

            return new ExtKey(results.Key, results.ChainCode);
        }


    }
}