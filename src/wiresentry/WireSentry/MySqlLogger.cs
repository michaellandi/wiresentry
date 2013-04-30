using System;
using System.Data;
using System.Linq;
using System.Threading;
using MySql.Data.MySqlClient;
using WireSentry.SDK;

namespace WireSentry
{
	public class MySqlLogger : IPacketLogger
	{
		private Semaphore _semaphore;

		protected IDebug Debugger { get; set; }
		protected MySqlConnection Connection { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.MySqlLogger"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// Debugger.
		/// </param>
		/// <param name='connection'>
		/// Connection.
		/// </param>
		public MySqlLogger(IDebug debugger, MySqlConnection connection)
		{
			//Ensure that only one database write occurs at a time.
			_semaphore = new Semaphore(1, 1);

			Debugger = debugger;
			Connection = connection;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="WireSentry.MySqlLogger"/> class.
		/// </summary>
		/// <param name='debugger'>
		/// The debugger instance to use for output.
		/// </param>
		/// <param name='connectionString'>
		/// The database's connection string.
		/// </param>
		public MySqlLogger(IDebug debugger, string connectionString)
		{
			//Ensure that only one database write occurs at a time.
			_semaphore = new Semaphore(1, 1);

			Debugger = debugger;
			Connection = new MySqlConnection(connectionString);
		}

		/// <summary>
		/// Opens a connection to the destination database.
		/// </summary>
		public virtual void Open()
		{
			try
			{
				Debugger.Status("Opening database connection...");

				//Attempt to open the database connection.
				Connection.Open();

				Debugger.Success();
			} 
			catch (Exception e)
			{
				//The database did not open correctly.
				Debugger.Failure(e);
				throw;
			}
		}

		/// <summary>
		/// Closes a connection to the destination database.
		/// </summary>
		public virtual void Close()
		{
			try
			{
				Debugger.Status("Closing database connection...");

				//Determine if the database connection is even open.
				if (Connection.State == ConnectionState.Open)
				{
					Connection.Close();
				}

				Debugger.Success();
			} 
			catch (Exception e)
			{ 
				Debugger.Failure(e);
			}
		}

		#region IPacketLogger implementation

		/// <summary>
		/// Creates a new event in the log.
		/// </summary>
		/// <param name='result'>
		/// The result of the scanner.
		/// </param>
		public virtual void Create(ScannerResult result)
		{
			try
			{
				_semaphore.WaitOne();

				//Reopen the connection if the connection is closed.
				if (Connection.State != ConnectionState.Open)
				{
					Open();
				}

				//Create the SQL records for this event.
				CreateSql(result);

				Debugger.Put(4, "\tdb: inserted new event '{0}'", ConsoleColor.DarkMagenta, result.Signature);
			} 
			catch (Exception e)
			{
				Debugger.Put(3, "\tdb: {0}", ConsoleColor.Red, e.Message);
			} 
			finally
			{
				_semaphore.Release();
			}
		}

		/// <summary>
		/// Updates an existing event in the log.
		/// </summary>
		/// <param name='result'>
		/// Result.
		/// </param>
		public virtual void Update(ScannerResult result)
		{
			try
			{
				_semaphore.WaitOne();

				//Reopen the connection if the connection is closed.
				if (Connection.State != ConnectionState.Open)
				{
					Open();
				}

				//Update an existing event with the new packets.
				UpdateSql(result);

				Debugger.Put(4, "\tdb: updated existing event '{0}'", ConsoleColor.DarkMagenta, result.Signature);
			} 
			catch (Exception e)
			{
				Debugger.Put(3, "\tdb: {0}", ConsoleColor.Red, e.Message);
			} 
			finally
			{
				_semaphore.Release();
			}
		}

		#endregion

		/// <summary>
		/// Creates the record in a mysql database.
		/// </summary>
		/// <param name='result'>
		/// The result to store in the database.
		/// </param>
		protected virtual void CreateSql(ScannerResult result)
		{
			/*
			 * Create a new event record in the database.
			 */
			var insertSql = string.Format("INSERT INTO `events` ({0},{1},{2},{3},{4},{5},{6}) " +
			                              "VALUES (@{0},@{1},@{2},@{3},@{4},@{5},@{6});",
			                              "signature",
			                              "start_date",
			                              "attack_address",
			                              "victim_address",
			                              "attack_type",
			                              "scanner_id",
			                              "last_activity");
			var first = result.Packets.OrderBy(x => x.Timestamp).First().Timestamp;
			var last = result.Packets.OrderBy(x => x.Timestamp).Last().Timestamp;
			var insert = new MySqlCommand(insertSql, Connection);
			insert.Parameters.Add("@signature", MySqlDbType.VarChar).Value = result.Signature;
			insert.Parameters.Add("@start_date", MySqlDbType.DateTime).Value = first;
			insert.Parameters.Add("@attack_address", MySqlDbType.VarChar).Value = result.AttackAddress;
			insert.Parameters.Add("@victim_address", MySqlDbType.VarChar).Value = result.VictimAddress;
			insert.Parameters.Add("@attack_type", MySqlDbType.VarChar).Value = result.AttackType;
			insert.Parameters.Add("@scanner_id", MySqlDbType.VarChar).Value = result.Scanner.Id;
			insert.Parameters.Add("@last_activity", MySqlDbType.DateTime).Value = last;
			insert.ExecuteNonQuery();
			
			/*
			 * Lookup the newly created event's id in the database.
			 * We need to the event id to associate the packets with the event.
			 */
			var lookupSql = "SELECT `id` FROM `events` WHERE `signature` = @signature;";
			var lookup = new MySqlCommand(lookupSql, Connection);
			lookup.Parameters.Add("@signature", MySqlDbType.VarChar).Value = result.Signature;
			var id = lookup.ExecuteScalar();
			
			/*
			 * Insert each packet into the database.
			 * Associate each packet with the newly created event.
			 */
			var packetSql = string.Format("INSERT INTO `packets` ({0},{1},{2},{3},{4},{5},{6}," + 
			                              "{7},{8},{9},{10},{11},{12}) " +
			                              "VALUES (@{0},@{1},@{2},@{3},@{4},@{5},@{6}," +
			                              "@{7},@{8},@{9},@{10},@{11},@{12});",
			                              "event_id",
			                              "port_source",
			                              "port_destination",
			                              "ip_address_source",
			                              "ip_address_destination",
			                              "domain_source",
			                              "domain_destination",
			                              "hardware_address_source",
			                              "hardware_address_target",
			                              "type",
			                              "payload",
			                              "timestamp",
			                              "protocol");
			foreach (var item in result.Packets)
			{
				var protocol = Enum.GetName(typeof(NetworkProtocol), item.Protocol);
				var packet = new MySqlCommand(packetSql, Connection);
				packet.Parameters.Add("@event_id", MySqlDbType.Int64).Value = id;
				packet.Parameters.Add("@port_source", MySqlDbType.Int32).Value = item.PortSource;
				packet.Parameters.Add("@port_destination", MySqlDbType.Int32).Value = item.PortDestination;
				packet.Parameters.Add("@ip_address_source", MySqlDbType.VarChar).Value = item.IpAddressSource;
				packet.Parameters.Add("@ip_address_destination", MySqlDbType.VarChar).Value = item.IpAddressDestination;
				packet.Parameters.Add("@domain_source", MySqlDbType.VarChar).Value = item.DomainSource;
				packet.Parameters.Add("@domain_destination", MySqlDbType.VarChar).Value = item.DomainDestination;
				packet.Parameters.Add("@hardware_address_source", MySqlDbType.VarChar).Value = item.HardwareAddressSource;
				packet.Parameters.Add("@hardware_address_target", MySqlDbType.VarChar).Value = item.HardwareAddressTarget;
				packet.Parameters.Add("@type", MySqlDbType.VarChar).Value = item.Type;
				packet.Parameters.Add("@payload", MySqlDbType.Blob).Value = item.Payload;
				packet.Parameters.Add("@timestamp", MySqlDbType.DateTime).Value = item.Timestamp;
				packet.Parameters.Add("@protocol", MySqlDbType.VarChar).Value = protocol;
				packet.ExecuteNonQuery();
				item.IsLogged = true;
			}
		}

		/// <summary>
		/// Updates an existing record in the database.
		/// </summary>
		/// <param name='result'>
		/// The result to update in the database.
		/// </param>
		protected virtual void UpdateSql(ScannerResult result)
		{
			var newPackets = result.Packets.Where(x => x.IsLogged == false);
			if (newPackets.Count() == 0)
			{
				return;
			}

			/*
			 * Lookup the id of the event that already exists in the database.
			 */
			var lookupSql = "SELECT `id` FROM `events` WHERE `signature` = @signature;";
			var lookup = new MySqlCommand(lookupSql, Connection);
			lookup.Parameters.Add("@signature", MySqlDbType.VarChar).Value = result.Signature;
			var id = lookup.ExecuteScalar();

			/*
			 * Update the existing event.
			 * Set the `last_activity` date to the timestamp of the oldest packet.
			 */
			var updateSql = "UPDATE `events` SET `last_activity` = @last_activity;";
			var last = result.Packets.OrderBy(x => x.Timestamp).Last().Timestamp;
			var update = new MySqlCommand(updateSql, Connection);
			update.Parameters.Add("@last_activity", MySqlDbType.DateTime).Value = last;
			update.ExecuteNonQuery();

			/*
			 * Insert each new packet into the database.
			 * Associate each packet with the existing event record.
			 */
			var packetSql = string.Format("INSERT INTO `packets` ({0},{1},{2},{3},{4},{5},{6}," + 
			                              "{7},{8},{9},{10},{11},{12}) " +
			                              "VALUES (@{0},@{1},@{2},@{3},@{4},@{5},@{6}," +
			                              "@{7},@{8},@{9},@{10},@{11},@{12});",
			                              "event_id",
			                              "port_source",
			                              "port_destination",
			                              "ip_address_source",
			                              "ip_address_destination",
			                              "domain_source",
			                              "domain_destination",
			                              "hardware_address_source",
			                              "hardware_address_target",
			                              "type",
			                              "payload",
			                              "timestamp",
			                              "protocol");
			foreach (var item in newPackets)
			{
				var protocol = Enum.GetName(typeof(NetworkProtocol), item.Protocol);
				var packet = new MySqlCommand(packetSql, Connection);
				packet.Parameters.Add("@event_id", MySqlDbType.Int64).Value = id;
				packet.Parameters.Add("@port_source", MySqlDbType.Int32).Value = item.PortSource;
				packet.Parameters.Add("@port_destination", MySqlDbType.Int32).Value = item.PortDestination;
				packet.Parameters.Add("@ip_address_source", MySqlDbType.VarChar).Value = item.IpAddressSource;
				packet.Parameters.Add("@ip_address_destination", MySqlDbType.VarChar).Value = item.IpAddressDestination;
				packet.Parameters.Add("@domain_source", MySqlDbType.VarChar).Value = item.DomainSource;
				packet.Parameters.Add("@domain_destination", MySqlDbType.VarChar).Value = item.DomainDestination;
				packet.Parameters.Add("@hardware_address_source", MySqlDbType.VarChar).Value = item.HardwareAddressSource;
				packet.Parameters.Add("@hardware_address_target", MySqlDbType.VarChar).Value = item.HardwareAddressTarget;
				packet.Parameters.Add("@type", MySqlDbType.VarChar).Value = item.Type;
				packet.Parameters.Add("@payload", MySqlDbType.Blob).Value = item.Payload;
				packet.Parameters.Add("@timestamp", MySqlDbType.DateTime).Value = item.Timestamp;
				packet.Parameters.Add("@protocol", MySqlDbType.VarChar).Value = protocol;
				packet.ExecuteNonQuery();
				item.IsLogged = true;
			}
		}
	}
}