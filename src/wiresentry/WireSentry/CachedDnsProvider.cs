using System;
using System.Collections.Specialized;
using System.Net;
using System.Threading;
using WireSentry.SDK;

namespace WireSentry
{
	public class CachedDnsProvider : IDnsProvider
	{
		private ReaderWriterLockSlim _lock;

		protected IDebug Debugger { get; set; }
		protected StringDictionary Hashtable { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.CachedDnsProvider"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// The debugger instance to use for debug output.
		/// </param>
		public CachedDnsProvider(IDebug debugger)
		{
			_lock = new ReaderWriterLockSlim();

			Debugger = debugger;
			Hashtable = new StringDictionary();
		}

		/// <summary>
		/// Gets the domain associated with the specified address.
		/// </summary>
		/// <param name='address'>
		/// The IP address of the domain to search for.
		/// </param>
		public string Get(string address)
		{
			//Attempt to read the entry from the hashtable first.
			_lock.EnterReadLock();
			var domain = Hashtable[address];
			_lock.ExitReadLock();

			//If the domain exists already just return it.
			if (!string.IsNullOrEmpty(domain))
			{
				return domain;
			}
			else //Domain did not exist.
			{
				//Lock the hashtable for writing.
				_lock.EnterWriteLock();

				try
				{
					/*
					 * Check awhile the thread is locked to ensure another thread
					 * did not alter the hashtable after the first lookup.
					 */
					domain = Hashtable[address];
					if (!string.IsNullOrEmpty(domain))
					{
						return domain;
					}

					//Attempt to resolve the ip address using the system's DNS providers.
					var host = Dns.GetHostEntry(address);
					if (host == null || string.IsNullOrEmpty(host.HostName))
					{
						return null;
					}

					Debugger.Put(5, "\tnslookup: " + host.HostName);

					//Add the address and domain name to the cache.
					Hashtable.Add(address, host.HostName);

					return host.HostName;
				}
				catch
				{
					return null;
				}
				finally
				{
					//Always release the write lock on the hastable.
					_lock.ExitWriteLock();
				}
			}
		}
	}
}

