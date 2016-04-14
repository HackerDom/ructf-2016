using Node.Connections;

namespace Node.Encryption
{
    internal interface IEncryptionConfig
    {
        IAddress KeyServerAddress { get; }
    }
}