using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Node.Connections;
using Node.Encryption;
using Node.Messages;
using Node.Routing;
using Node.Serialization;

namespace Node.Data
{
    internal class DataManager : IDataManager
    {
        public DataManager(IDataStorage dataStorage, string dataFilePath, IRoutingManager routingManager, IEncryptionManager encryptionManager)
        {
            this.dataStorage = dataStorage;
            this.dataFilePath = dataFilePath;
            this.routingManager = routingManager;
            this.encryptionManager = encryptionManager;
            pendingMessages = new List<QueueEntry>();
        }

        public bool ProcessMessage(IMessage message, IConnection connection)
        {
            if (message == null)
                return true;
            return
                ProcessData(message as DataMessage) ||
                ProcessRedirect(message as RedirectMessage);
        }

        public void PushMessages(IEnumerable<IConnection> readyConnections)
        {
            foreach (var connection in readyConnections)
            {
                var pending = pendingMessages.FirstOrDefault(m => Equals(m.Destination, connection.RemoteAddress));
                if (pending.Destination == null)
                    continue;

                var result = pending.Message != null ? connection.Push(pending.Message) : connection.Push(pending.RawData);
                if (result == SendResult.Success)
                {
                    pendingMessages.Remove(pending);
                }
            }
        }

        public void FlushData()
        {
            using (var stream = File.Create(dataFilePath))
                new StreamSerializer(stream).Write(dataStorage);
        }

        public void DispatchData(string key, byte[] data, IAddress destination)
        {
            var message = new DataMessage(DataAction.Put, key, data, routingManager.Map.OwnAddress);
            //TODO send by 3 paths
            var wrapped = WrapMessage(message, destination,
                routingManager.Map.Links.CreatePath(routingManager.Map.OwnAddress, destination).GetPathBody());
            pendingMessages.Add(new QueueEntry(wrapped, message, destination));
        }

        public void RequestData(string key, IAddress destination)
        {
            var message = new DataMessage(DataAction.Get, key, new byte[0], routingManager.Map.OwnAddress);
            //TODO send by 3 paths
            var wrapped = WrapMessage(message, destination,
                routingManager.Map.Links.CreatePath(routingManager.Map.OwnAddress, destination).GetPathBody());
            pendingMessages.Add(new QueueEntry(wrapped, message, destination));
        }

        public event Action<DataMessage> OnReceivedData = data => { };

        public void PullPendingMessage(IConnection connection)
        {
            var message = pendingMessages
                .FirstOrDefault(m => Equals(m.Destination, connection.RemoteAddress) && m.UnwrappedMessage != null);
            if (message.UnwrappedMessage == null)
                return;
            var result = connection.Push(message.UnwrappedMessage);
            if (result == SendResult.Success)
            {
                pendingMessages.Remove(message);
            }
        }

        private IMessage WrapMessage(IMessage message, IAddress destination, List<IAddress> path)
        {
            while (path.Count > 0)
            {
                var length = new MessageContainer(message).WriteToBuffer(serializerBuffer, 0);
                encryptionManager.CreateEncoder(path.Last()).ProcessBeforeSend(MessageType.Data, serializerBuffer, 0, length);
                //TODO optimize
                var wrapped = new RedirectMessage(destination, serializerBuffer.Take(length).ToArray());
                message = wrapped;
                path.RemoveAt(path.Count - 1);
            }
            return message;
        }

        private bool ProcessRedirect(RedirectMessage redirectMessage)
        {
            if (redirectMessage == null)
                return false;

            pendingMessages.Add(new QueueEntry(redirectMessage.Data, redirectMessage.Destination));
            return true;
        }

        private bool ProcessData(DataMessage dataMessage)
        {
            if (dataMessage == null)
                return false;

            switch (dataMessage.Action)
            {
                case DataAction.None:
                    OnReceivedData(dataMessage);
                    break;
                case DataAction.Put:
                    dataStorage.PutData(dataMessage.Key, dataMessage.Data);
                    break;
                case DataAction.Get:
                    var data = dataStorage.GetData(dataMessage.Key);
                    if (data != null)
                        DispatchData(dataMessage.Key, data, dataMessage.Source);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
            return true;
        }

        private readonly List<QueueEntry> pendingMessages;

        private readonly IDataStorage dataStorage;
        private readonly string dataFilePath;
        private readonly IRoutingManager routingManager;
        private readonly IEncryptionManager encryptionManager;

        private readonly byte[] serializerBuffer = new byte[1024 * 1024 * 4];

        private struct QueueEntry
        {
            public QueueEntry(IMessage message, IMessage unwrappedMessage, IAddress destination)
            {
                Message = message;
                UnwrappedMessage = unwrappedMessage;
                Destination = destination;
                RawData = null;
            }
            public QueueEntry(byte[] rawData, IAddress destination)
            {
                RawData = rawData;
                Destination = destination;
                Message = null;
                UnwrappedMessage = null;
            }

            public readonly IMessage Message;
            public readonly IMessage UnwrappedMessage;
            public readonly byte[] RawData;
            public readonly IAddress Destination;
        }
    }
}