using System;

namespace WireSentry
{
	public interface IDnsProvider
	{
		/// <summary>
		/// Gets the domain associated with the specified address.
		/// </summary>
		/// <param name='address'>
		/// The IP address of the domain to search for.
		/// </param>
		string Get(string address);
	}
}

