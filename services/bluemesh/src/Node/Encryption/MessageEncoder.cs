using System;
using Node.Messages;

namespace Node.Encryption
{
    internal class MessageEncoder : IMessageEncoder
    {
        public MessageEncoder(ulong privateKey, Func<ulong> publicKeyProvider)
        {
            this.privateKey = privateKey;
            this.publicKeyProvider = publicKeyProvider;
        }

        public void ProcessAfterReceive(MessageType messageType, byte[] buffer, int offset, int length)
        {
            if (messageType != MessageType.Data && messageType != MessageType.Redirect)
                return;
            //Console.WriteLine("Decoded message of type {0} with key {1}", messageType, privateKey);
            BluemeshEncryptor.EncryptBytes(buffer, offset, 
                length % 8 == 0 ? length : length + (8 - length % 8), privateKey);
        }

        public void ProcessBeforeSend(MessageType messageType, byte[] buffer, int offset, int length)
        {
            if (messageType != MessageType.Data && messageType != MessageType.Redirect)
                return;
            var publicKey = publicKeyProvider();
            //Console.WriteLine("Encoded message of type {0} with key {1}", messageType, publicKey);
            BluemeshEncryptor.EncryptBytes(buffer, offset,
                length % 8 == 0 ? length : length + (8 - length % 8), publicKey);
        }

        private readonly ulong privateKey;
        private readonly Func<ulong> publicKeyProvider;
    }
}