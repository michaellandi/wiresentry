using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.Linq;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using Mono.Unix;
using Mono.Unix.Native;
using SharpPcap;
using WireSentry.SDK;

namespace WireSentry
{
	public class Daemon
	{
		/// <summary>
		/// The size of the packet cache by default.
		/// </summary>
		private const int CACHE_SIZE = 0xFFFF;

		private ReaderWriterLockSlim _cachelock;
		protected virtual string Device { get; set; }
		protected virtual IDebug Debugger { get; set; }
		protected virtual IPacketProcessor Processor { get; set; }
		protected virtual IPacketLogger Logger { get; set; }
		protected virtual IDataPacketCollection Cache { get; set; }
		protected virtual ModuleManager ModuleEngine { get; set; }
		protected virtual IDictionary<string, ScannerResult> Results { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.Daemon"/> class.
		/// </summary>
		public Daemon(int verbosity, string device, string connectionString)
		{
			_cachelock = new ReaderWriterLockSlim();

			Device = device;
			Results = new Dictionary<string, ScannerResult>();
			Debugger = new ConsoleDebug(verbosity);
			Cache = new DataPacketQueue(CACHE_SIZE);
			Processor = new PacketProcessor(new CachedDnsProvider(Debugger));
			ModuleEngine = new ModuleManager(Debugger);

			if (string.IsNullOrEmpty(connectionString))
			{
				Logger = new NullLogger();
			} 
			else
			{
				Logger = new MySqlLogger(Debugger, connectionString);
			}
		}

		/// <summary>
		/// Handles a packet when it is captured from the specified interface.
		/// </summary>
		/// <param name='sender'>
		/// Sender.
		/// </param>
		/// <param name='e'>
		/// E.
		/// </param>
		protected virtual void HandleOnPacketArrival(object sender, CaptureEventArgs e)
		{
			//Determine if the packet is a type of packet that we know how to handle already.
			var packet = Processor.Process(e.Packet);
			if (packet == null)
			{
				//If we can't handle it just discard the packet.
				return;
			}
			
			//Enter write lock for the cache (we're going to be adding a record)
			_cachelock.EnterWriteLock();
			Cache.Add(packet);
			_cachelock.ExitWriteLock();
			
			Debugger.Put(5, packet.ToString());
		}

		/// <summary>
		/// Handles a module when it should execute.
		/// </summary>
		/// <param name='s'>
		/// The module which should execute.
		/// </param>
		/// <param name='e'>
		/// E.
		/// </param>
		protected virtual void HandleModuleShouldExecute(Scanner s, EventArgs e)
		{
			//Enter read lock for one of the scanners.
			_cachelock.EnterReadLock();
			var results = s.Scan(Cache);
			_cachelock.ExitReadLock();
			
			//See if there are any results from the scanner and print if true.
			foreach (var result in results)
			{
				/* 
				 * Don't store duplicate entries for this attack,
				 * It has already happened!  Instead update the existing attack
				 * with the new attack packets.
				 */
				if (Results.ContainsKey(result.Signature))
				{
					//Update existing collection of packets and database
					var existing = Results[result.Signature];
					var pcount = existing.Packets.Count();
					existing.AddPackets(result.Packets);
					if (pcount == existing.Packets.Count())
					{
						//Nothing new at all happened.
						continue;
					}

					//Notify the logging destination that the attack was updated.
					Logger.Update(existing);
					
					//Notify console user that a significant event occurred.
					Console.Beep();
					Debugger.Put(3, "\tscanner: Updated {0} ({1} packets)",
					             ConsoleColor.DarkYellow,
					             result.Signature,
					             existing.Packets.Count());
				}
				else
				{
					//Add new result to collection of packets and database.
					Results.Add(result.Signature, result);
					Logger.Create(result);

					Console.Beep();
					Debugger.Put(2, "{0}\n\t\tModule: {1} ({2})\n\t\tSignature: {3}", 
					             ConsoleColor.DarkYellow,
					             result.ToString(),
					             result.Scanner.Name,
					             result.Scanner.Version,
					             result.Signature);

					//Loop through each handler and process the results.
					ModuleEngine.Handlers.ToList().ForEach(x => x.Handle(result));
				}
			}
		}

		/// <summary>
		/// Gets the specified interface device.
		/// </summary>
		/// <returns>
		/// The interface device on which to capture.
		/// </returns>
		/// <param name='name'>
		/// The name of the interface on which to capture (ie. 'en2').
		/// </param>
		protected virtual ICaptureDevice GetDevice(string name)
		{
			var devices = CaptureDeviceList.Instance.Where(dev => dev.Name == name);
			if (devices.Count() == 0)
			{
				throw new Exception("The device '" + name + "' was not found.");
			}
			
			return devices.Single();
		}

		public virtual void Initialize(bool promiscuous)
		{
			ICaptureDevice device = null;

			//Attempt to load modules in the current directory.
			ModuleEngine.Load(UnixEnvironment.CurrentDirectory);
			ModuleEngine.ScannerShouldExecute += HandleModuleShouldExecute;

			//Open the logger for output.
			try
			{
				Logger.Open();
			}
			catch
			{
				Debugger.Put(1, "Proceeding without logging!", ConsoleColor.DarkMagenta);
				Logger = new NullLogger();
			}

			/*
			 * Attempt to open the specified device for capturing.
			 */
			try
			{
				//Attempt to open the device interface for capture.
				Debugger.Status("Opening device '" + Device + "' for capture...");

				//Configure device for packet capture.
				device = GetDevice(Device);
				device.OnPacketArrival += HandleOnPacketArrival; 

				//Open the device depending on the mode specified.
				if (promiscuous)
				{
					device.Open(DeviceMode.Promiscuous);
				}
				else
				{
					device.Open(DeviceMode.Normal);
				}

				Debugger.Success();
			} 
			catch (Exception e)
			{
				Debugger.Failure(e);
				Environment.Exit(-1);
			}

			/*
			 * Attempt to start capturing packets on the device.
			 */
			try
			{
				Debugger.Status("Starting capture on device '" + Device + "'");

				//Wait two seconds for modules to load before starting capture.
				Thread.Sleep(2000);
				device.StartCapture();

				Debugger.Success();
			} 
			catch (Exception e)
			{
				Debugger.Failure(e);
				Environment.Exit(-2);
			}

			//Start module scheduler thread.
			ModuleEngine.StartScheduler();

			//Waits for a UNIX kill signal.
			UnixSignal.WaitAny(new UnixSignal [] {
				new UnixSignal(Signum.SIGINT),
				new UnixSignal(Signum.SIGTERM),
				new UnixSignal(Signum.SIGQUIT),
				new UnixSignal(Signum.SIGHUP) });

			/*
			 * At this point a kill signal has been received and
			 * the shutdown process can begin.
			 * 
			 * Stop capturing and stop modules from running.
			 */
			Debugger.Put(3, "Terminate signal received");
			ModuleEngine.StopScheduler();
			Logger.Close();
			device.StopCapture();
			Thread.Sleep(2000);

			/*
			 * Kill signal received, attempt to close the listening device.
			 */
			try
			{
				Debugger.Status("Attempting to close device...");

				//Close the interface from packet capturing.
				device.Close();

				Debugger.Success();
			} 
			catch (Exception e)
			{
				Debugger.Failure(e);
			}

			//Exit with success!
			Environment.Exit(0);
		}
	}
}