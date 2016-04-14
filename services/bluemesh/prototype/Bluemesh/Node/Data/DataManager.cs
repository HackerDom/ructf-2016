using System;
using System.Collections.Generic;
using System.IO;
using Node.Connections;
using Node.Messages;
using Node.Serialization;

namespace Node.Data
{
    internal class DataManager : IDataManager
    {
        public DataManager(IDataStorage dataStorage, string dataFilePath)
        {
            this.dataStorage = dataStorage;
            this.dataFilePath = dataFilePath;
            pendingMessages = new List<QueueEntry>();
        }

        public bool ProcessMessage(IMessage message, IConnection connection)
        {
            if (message == null)
                return true;
            return
                ProcessData(message as DataMessage, connection) ||
                ProcessRedirect(message as RedirectMessage, connection);
        }

        public void PushMessages(IEnumerable<IConnection> readyConnections)
        {
            throw new NotImplementedException();
        }

        public void FlushData()
        {
            using (var stream = File.Create(dataFilePath))
                new StreamSerializer(stream).Write(dataStorage);
        }

        public void DispatchData(string key, byte[] data, IAddress destination)
        {
            throw new NotImplementedException();
        }

        public void RequestData(string key, IAddress destination)
        {
            throw new NotImplementedException();
        }

        public event Action<DataMessage> OnReceivedData = data => { };

        private void EnqueueOutgoingMessage(IMessage message, IAddress destination)
        {
            
        }

        private bool ProcessRedirect(RedirectMessage redirectMessage, IConnection connection)
        {
            if (redirectMessage == null)
                return false;

            //TODO enqueue raw data
            throw new NotImplementedException();
        }

        private bool ProcessData(DataMessage dataMessage, IConnection connection)
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

        private struct QueueEntry
        {
            public QueueEntry(IMessage message, IAddress destination)
            {
                Message = message;
                Destination = destination;
            }

            public readonly IMessage Message;
            public readonly IAddress Destination;
        }
    }
}