using System.Collections.Generic;
using Node.Connections;

namespace Node.Encryption
{
    internal interface IEncryptionManager
    {
        void GenerateKeyPair(byte[] seed);

        void Start();

        void Stop();

        void RetrievePeerKeys(IEnumerable<IAddress> peers);

        IMessageEncoder CreateEncoder(IAddress peer);
    }
}