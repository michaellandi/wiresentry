using System;

namespace WireSentry.SDK
{
	/// <summary>
	/// A representation of captured network traffic.
	/// </summary>
	public class DataPacket
	{
		public Guid Id { get; protected set; }
		public int PortSource { get; set; }
		public int PortDestination { get; set; }
		public string IpAddressSource { get; set; }
		public string IpAddressDestination { get; set; }
		public string DomainSource { get; set; }
		public string DomainDestination { get; set; }
		public string HardwareAddressSource { get; set; }
		public string HardwareAddressTarget { get; set; }
		public string Type { get; set; }
		public byte[] Payload { get; set; }
		public DateTime Timestamp { get; set; }
		public NetworkProtocol? Protocol { get; set; }
		public bool IsLogged { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.SDK.DataPacket"/> class.
		/// </summary>
		public DataPacket() 
		{
			//Sets a unique id so this packet can be identified at a later time.
			Id = Guid.NewGuid();
		}

		/// <summary>
		/// Returns a <see cref="System.String"/> that represents the current <see cref="WireSentry.SDK.DataPacket"/>.
		/// </summary>
		/// <returns>
		/// A <see cref="System.String"/> that represents the current <see cref="WireSentry.SDK.DataPacket"/>.
		/// </returns>
		public override string ToString()
		{
			if (Protocol.HasValue && Protocol == NetworkProtocol.arp)
			{
				return string.Format("\tcapture: {0} {1} -> {2} (Length: {3})",
				                     Protocol.HasValue ? Enum.GetName(typeof(NetworkProtocol), Protocol) : string.Empty,
				                     HardwareAddressSource ?? string.Empty,
				                     HardwareAddressTarget ?? string.Empty,
				                     Payload == null ? 0 : Payload.Length);
			} 
			else
			{
				return string.Format("\tcapture: {0} {1}:{2} -> {3}:{4} (Length: {5})",
				                     Protocol.HasValue ? Enum.GetName(typeof(NetworkProtocol), Protocol) : string.Empty,
			                     	 IpAddressSource ?? string.Empty,
			                     	 PortSource,
			                     	 IpAddressDestination ?? string.Empty,
			                     	 PortDestination,
			                     	 Payload == null ? 0 : Payload.Length);
			}
		}
	}
}