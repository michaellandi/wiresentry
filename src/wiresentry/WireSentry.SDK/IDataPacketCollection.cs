using System;
using System.Collections.Generic;

namespace WireSentry.SDK
{
	/// <summary>
	/// A collection of data packets.
	/// </summary>
	public interface IDataPacketCollection
	{
		/// <summary>
		/// Gets the number of elements in the collection.
		/// </summary>
		/// <value>
		/// The count of the collection.
		/// </value>
		int Count { get; }

		/// <summary>
		/// Adds the specified packet to the collection.
		/// </summary>
		/// <param name='packet'>
		/// The packet to add to the collection.
		/// </param>
		void Add(DataPacket packet);

		/// <summary>
		/// Gets the collection of packets stored in the collection.
		/// </summary>
		/// <value>
		/// The items stored in the collection.
		/// </value>
		IEnumerable<DataPacket> Items { get; }
	}
}