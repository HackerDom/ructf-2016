using Node.Messages;

namespace Node.Encryption
{
    internal interface IMessageEncoder
    {
        void ProcessAfterReceive(MessageType messageType, byte[] buffer, int offset, int length);
        void ProcessBeforeSend(MessageType messageType, byte[] buffer, int offset, int length);
    }
}