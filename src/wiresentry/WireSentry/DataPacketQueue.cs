using System;
using System.Collections.Generic;
using WireSentry.SDK;

namespace WireSentry
{
	public class DataPacketQueue : IDataPacketCollection
	{
		protected virtual int MaxSize { get; set; }
		protected virtual Queue<DataPacket> PacketQueue { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.DataPacketQueue"/> class.
		/// </summary>
		/// <param name='maxSize'>
		/// The maximum size of the queue.
		/// </param>
		public DataPacketQueue(int maxSize)
		{
			MaxSize = maxSize;
			PacketQueue = new Queue<DataPacket>(maxSize);
		}

		/// <summary>
		/// Adds the specified packet to the queue.
		/// </summary>
		/// <param name='packet'>
		/// The packet to add to the queue.
		/// </param>
		public virtual void Add(DataPacket packet)
		{
			//If the queue is full dequeue the first element.
			while (Count >= MaxSize)
			{
				PacketQueue.Dequeue();
			}

			//Enqueue the packet.
			PacketQueue.Enqueue(packet);
		}

		/// <summary>
		/// Gets the number of elements in the Queue.
		/// </summary>
		/// <value>
		/// The count of the Queue.
		/// </value>
		public virtual int Count
		{
			get
			{
				return PacketQueue.Count;
			}
		}

		/// <summary>
		/// Gets the collection of packets stored in the Queue.
		/// </summary>
		/// <value>
		/// The items stored in the Queue.
		/// </value>
		public IEnumerable<DataPacket> Items
		{
			get
			{
				return PacketQueue;
			}
		}
	}
}

