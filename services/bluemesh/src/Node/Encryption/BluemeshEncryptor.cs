using System;

namespace Node.Encryption
{
    internal static class BluemeshEncryptor
    {
        public static unsafe void EncryptBytes(byte[] bytes, int offset, int length, ulong key)
        {
            if (length % 8 > 0)
                throw new ArgumentException("Length should be a multiple of 8!", nameof(length));
            fixed (byte* data = bytes)
            {
                var mptr = (ulong*) (data + offset);
                for (int i = 0; i < length / 8; i++)
                {
                    *(mptr + i) *= key;
                }
            }
        }

        public static ulong GeneratePublicKey(ulong privateKey)
        {
            ulong x, y;
            if (Gcd((ulong.MaxValue % privateKey) + 1, privateKey, out x, out y) != 1)
                throw new ArgumentException("Invalid private key provided!", nameof(privateKey));
            return y - (ulong.MaxValue / privateKey) * x;
        }

        public static ulong GeneratePrivateKey(byte[] seed)
        {
            ulong hash = 0;
            for (int i = 0; i < seed.Length || hash % 2 == 0; i++)
                hash = (seed[i % seed.Length] + (ulong)(i / seed.Length) + hash) * 167;
            return hash;
        }

        private static ulong Gcd(ulong a, ulong b, out ulong x, out ulong y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }
            ulong x1, y1;
            ulong d = Gcd(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }
    }
}
