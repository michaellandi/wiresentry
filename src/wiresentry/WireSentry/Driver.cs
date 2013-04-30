using System;
using System.IO;
using Mono.Options;
using MySql.Data.MySqlClient;

namespace WireSentry
{
	/// <summary>
	/// Responsible for parsing CLI arguments and instantiating `Daemon` class.
	/// </summary>
	public class Driver
	{
		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		/// <param name='args'>
		/// The command-line arguments.
		/// </param>
		public static void Main(string[] args)
		{
			//Print the informational banner about the application.
			Console.WriteLine("------------------------------------------------------");
			Console.WriteLine("|  Wire Sentry                           Version 0.9 |");
			Console.WriteLine("|  Copyright © 2013 Michael Landi                    |");
			Console.WriteLine("|                                                    |");
			Console.WriteLine("|  mlandi@sourcesecure.net                           |");
			Console.WriteLine("|  http://www.sourcesecure.net                       |");
			Console.WriteLine("------------------------------------------------------");
			Console.WriteLine("\n");
			
			//CLI options.
			var device = string.Empty;
			var connection_string = string.Empty;
			var verbosity = 0;
			var show_help = false;
			var promiscuous = true;
			
			//Declare a new set of CLI options.
			var p = new OptionSet() {
				{ "d|device=", "the name of the {DEVICE} to capture",
					v => device = v },
				{ "c=", 
					"the database {CONNECTION} string",
					v => connection_string = v },
				{ "v", "increase debug message verbosity",
					v => { if (v != null) ++verbosity; } },
				{ "n|normal", "don't use promiscuous mode",
					v => promiscuous = true },
				{ "h|help",  "show this message and exit", 
					v => show_help = v != null },
			};
			
			try
			{
				//Attempt to parse the CLI arguments using the specified CLI options.
				p.Parse(args);
			} 
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
				show_help = true;
			}

			try
			{
				//Determine if the connection string is in the correct format.
				if (!string.IsNullOrEmpty(connection_string))
				{
					var connection = new MySqlConnection(connection_string);
					connection.Dispose();
				}
			}
			catch
			{
				Console.WriteLine("error: Connection string is not in the correct format!");
				Console.WriteLine("\tPlease see http://www.connectionstrings.com/mysql for more information.");
				Environment.Exit(-1);
			}
			
			//Show help screen if neccessary.
			if (show_help || string.IsNullOrEmpty(device))
			{
				var writer = new StringWriter();
				p.WriteOptionDescriptions(writer);

				Console.WriteLine("usage: wsentryd -d {DEVICE} -c {CONNECTION_STRING} -v\n");
				Console.WriteLine(writer.ToString());
				Environment.Exit(0);
			}
			
			//Instantiate a new instance of the class and pass in the CLI options.
			new Daemon(verbosity, device, connection_string).Initialize(promiscuous);
		}
	}
}