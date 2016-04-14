using Node.Messages;

namespace Node.Encryption
{
    internal class MessageEncoder : IMessageEncoder
    {
        public MessageEncoder(ulong privateKey, ulong publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public void ProcessAfterReceive(MessageType messageType, byte[] buffer, int offset, int length)
        {
            if (messageType != MessageType.Data)
                return;
            BluemeshEncryptor.EncryptBytes(buffer, offset, 
                length % 8 == 0 ? length : length + (8 - length % 8), privateKey);
        }

        public void ProcessBeforeSend(MessageType messageType, byte[] buffer, int offset, int length)
        {
            if (messageType != MessageType.Data)
                return;
            BluemeshEncryptor.EncryptBytes(buffer, offset,
                length % 8 == 0 ? length : length + (8 - length % 8), publicKey);
        }

        private readonly ulong privateKey;
        private readonly ulong publicKey;
    }
}