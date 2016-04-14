using Node.Connections;

namespace Node.Encryption
{
    internal interface IEncryptionManager
    {
        void GenerateKeyPair(byte[] seed);

        void Start();

        void Stop();

        IMessageEncoder CreateEncoder(IAddress peer);
    }
}