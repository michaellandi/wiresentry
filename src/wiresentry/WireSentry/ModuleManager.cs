using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using WireSentry.SDK;
using System.Threading;

namespace WireSentry
{
	public class ModuleManager
	{
		public const int SCHEDULER_INTERVAL = 250;

		protected virtual IDebug Debugger { get; set; }
		protected virtual IDictionary<Guid, Handler> HandlerList { get; set; }
		protected virtual IDictionary<Guid, Scanner> ScannerList { get; set; }
		protected virtual IDictionary<Guid, DateTime> ScheduledList { get; set; }
		protected virtual System.Timers.Timer Scheduler { get; set; }

		/// <summary>
		/// Occurs when a module should execute.
		/// </summary>
		public event ScannerShouldExecuteHandler ScannerShouldExecute;
		public delegate void ScannerShouldExecuteHandler(Scanner s, EventArgs e);

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.ModuleManager"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// The debugger instance to use for debug output.
		/// </param>
		public ModuleManager(IDebug debugger)
		{
			Debugger = debugger;
			HandlerList = new Dictionary<Guid, Handler>();
			ScannerList = new Dictionary<Guid, Scanner>();
			ScheduledList = new Dictionary<Guid, DateTime>();

			Scheduler = new System.Timers.Timer();
			Scheduler.Interval = SCHEDULER_INTERVAL;
			Scheduler.Elapsed += SchedulerElapsed;
		}

		/// <summary>
		/// Occurs when the scheduler needs to check if a module is ready to execute.
		/// </summary>
		/// <param name='sender'>
		/// The Sender.
		/// </param>
		/// <param name='e'>
		/// Event Arguments.
		/// </param>
		protected void SchedulerElapsed(object sender, System.Timers.ElapsedEventArgs e)
		{
			lock (ScannerList)
			{
				//Loop through the modules to check if any modules are ready to run.
				foreach (var module in ScannerList.Values)
				{
					//Is it passed time to run the module?
					if (DateTime.Now < ScheduledList[module.Id])
					{
						continue;
					}

					Debugger.Put(4, "\tscheduler: running scanner '{0}'", ConsoleColor.DarkCyan, module.Name);
					
					/*
					 * Notify any callback event handlers that the module is ready to be run.
					 * We don't actually run the event ourselves.
					 * After running the module we need to update the next run time for the scheduler.
					 */
					ScannerShouldExecute(module, EventArgs.Empty);
					ScheduledList[module.Id] = DateTime.Now.AddSeconds(module.Frequency);
				}
			}
		}

		/// <summary>
		/// Returns a collection of the loaded scanners.
		/// </summary>
		/// <value>
		/// The scanners as a collection.
		/// Note:  this collection is copied before being returned (a handle to the 
		/// module manager's collection is not permitted due to concurrency and locking requirements).
		/// </value>
		public virtual IEnumerable<Scanner> Scanners
		{
			get
			{
				lock (ScannerList)
				{
					//Copy the current collection to a new array and return it.
					var buffer = new Scanner[ScannerList.Count];
					ScannerList.Values.CopyTo(buffer, 0);
					
					return buffer;
				}
			}
		}

		/// <summary>
		/// Returns a collection of the loaded handlers.
		/// </summary>
		/// <value>
		/// The handlers as a collection.
		/// Note:  this collection is copied before being returned (a handle to the 
		/// module manager's collection is not permitted due to concurrency and locking requirements).
		/// </value>
		public virtual IEnumerable<Handler> Handlers
		{
			get
			{
				lock (HandlerList)
				{
					//Copy the current collection to a new array and return it.
					var buffer = new Handler[HandlerList.Count];
					HandlerList.Values.CopyTo(buffer, 0);

					return buffer;
				}
			}
		}

		/// <summary>
		/// Starts executing modules by starting the scheduler.
		/// </summary>
		public void StartScheduler()
		{
			Scheduler.Start();
		}

		/// <summary>
		/// Stops executing modules by stopping the scheduler.
		/// </summary>
		public void StopScheduler()
		{
			Scheduler.Stop();;
		}

		/// <summary>
		/// Unloads a module with the specified id.
		/// </summary>
		/// <param name='id'>
		/// The identifier of the module to unload.
		/// </param>
		public virtual void Unload(Guid id)
		{
			lock (ScannerList)
			{
				try
				{
					Debugger.Status("Attempt to remove module: " + id.ToString());

					//Remove the scanner items and invoke garbage collection.
					if (ScannerList.ContainsKey(id))
					{
						ScannerList.Remove(id);
						ScheduledList.Remove(id);
					}
					else if (HandlerList.ContainsKey(id))
					{
						HandlerList.Remove(id);
					}
					else
					{
						throw new Exception("Module not found.");
					}

					GC.Collect();
					Debugger.Success();
				}
				catch (Exception e)
				{
					Debugger.Failure(e);
				}
			}
		}

		/// <summary>
		/// Loads the scanner modules stored in a specified path.
		/// </summary>
		/// <param name='path'>
		/// The path that should be searched for scanners.
		/// </param>
		public virtual void Load(string path)
		{
			var handlersToLoad = new List<Type>();
			var scannersToLoad = new List<Type>();

			try
			{
				Debugger.Status("Searching for loadable modules...");

				// Determine if the directory actually exists before attempting to load the directory.
				if (!Directory.Exists(path))
				{
					throw new DirectoryNotFoundException();
				}

				//Loop through all of the assembly files in the directory.
				foreach (var file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories).Where(
					f => f.EndsWith(".exe", StringComparison.CurrentCultureIgnoreCase) ||
						 f.EndsWith(".dll", StringComparison.CurrentCultureIgnoreCase)))
				{
					try
					{
						/*
						 * Load each assembly into memory and attempt to search it for any `Scanner` types.
						 */
						var assembly = Assembly.LoadFile(file);
						foreach (var type in assembly.GetTypes())
						{
							if (type.IsSubclassOf(typeof(Scanner)))
							{
								//Add this module to the list of scanners to load.
								scannersToLoad.Add(type);
							}

							if (type.IsSubclassOf(typeof(Handler)))
							{
								//Add this module to the list of handlers to load.
								handlersToLoad.Add(type);
							}
						}
					}
					catch { continue; }
				}

				//Notify user that searching was successful, as well as the number of modules found.
				Debugger.Success();
				Debugger.Put(2, "\tFound {0} loadable modules", Console.ForegroundColor, scannersToLoad.Count);
				Debugger.Put(1, "Loading modules into memory...");

				lock (ScannerList)
				{
					foreach (var type in scannersToLoad)
					{
						/*
						 * LOAD SCANNERS
						 */
						try
						{
							Debugger.Status("\tLoading scanner '" + type.Name + "'");

							/*
							 * Create a new instance of the class and determine if the class has
							 * been previously loaded (we ignore duplicates--first come, first server).
							 */
							var module = (Scanner)Activator.CreateInstance(type, new[] { Debugger });
							if (ScannerList.ContainsKey(module.Id))
							{
								throw new Exception("Scanner has already been added!");
							}

							/*
							 * Create entries for the module in the scheduler list as well as the
							 * module list.  The next run date is computed based on the module frequency.
							 */
							ScannerList.Add(module.Id, module);
							ScheduledList.Add(module.Id, DateTime.Now.AddSeconds(module.Frequency));
							
							Debugger.Success();
							Debugger.Put(3, "\t\tId: {0}\n\t\tVersion: {1}", 
							             ConsoleColor.DarkCyan,
							             module.Id,
							             module.Version);
						}
						catch (Exception e)
						{
							Debugger.Failure(e.InnerException ?? e);
						}
					}
				}

				lock (HandlerList)
				{
					/*
					 * LOAD HANDLERS
					 */
					try
					{
						foreach (var type in handlersToLoad)
						{
							Debugger.Status("\tLoading handler '" + type.Name + "'");

							/*
							 * Create a new instance of the class and determine if the class has
							 * been previously loaded (we ignore duplicates--first come, first server).
							 */
							var module = (Handler)Activator.CreateInstance(type, new[] { Debugger });
							if (HandlerList.ContainsKey(module.Id))
							{
								throw new Exception("Handler has already been added!");
							}

							//Add this handler to the list of handlers.
							HandlerList.Add(module.Id, module);
							
							Debugger.Success();
							Debugger.Put(3, "\t\tId: {0}\n\t\tVersion: {1}", 
							             ConsoleColor.DarkCyan,
							             module.Id,
							             module.Version);
						}
					}
					catch (Exception e)
					{
						Debugger.Failure(e.InnerException ?? e);
					}
				}
			} 
			catch (Exception e)
			{
				Debugger.Failure(e);

				//If the module path specified didn't exist we should exit after notifying the user!
				Environment.Exit(-200);
			}
		}
	}
}