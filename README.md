# Wire Sentry

Last updated: April 20, 2026

**Wire Sentry** is a modular network intrusion detection system (IDS) framework written in C# for the [Mono](http://www.mono-project.com) runtime. It captures live network traffic and runs it through a set of pluggable scanner modules to identify malicious activity in real time.

For more information, see the [design document](wiresentry.pdf).

## Features

- Live packet capture via [SharpPcap](https://github.com/dotpcap/sharppcap)
- Modular scanner architecture — load custom detectors as DLL plugins at runtime
- Built-in scanners for common attack patterns:
  - **Port scan detection** — identifies sequential TCP port sweeps
  - **ARP spoofing detection**
  - **DNS spoofing detection**
- Optional MySQL logging of scan results
- Daemon mode for continuous background monitoring
- Ruby on Rails web interface (`src/wiresentry-web`) for viewing results
- SDK (`WireSentry.SDK`) for building your own scanner modules

## Requirements

- [Mono](http://www.mono-project.com) runtime
- [SharpPcap](https://github.com/dotpcap/sharppcap) / PacketDotNet
- MySQL (optional, for result logging)
- libpcap / WinPcap

## Usage

```
wsentryd -d {DEVICE} -c {CONNECTION_STRING} [-v]

Options:
  -d, --device=DEVICE      Network interface to capture on
  -c                       MySQL connection string (optional)
  -v                       Increase debug verbosity (repeatable)
  -n, --normal             Disable promiscuous mode
  -h, --help               Show help
```

**Example:**
```bash
sudo mono WireSentry.exe -d eth0 -v
sudo mono WireSentry.exe -d eth0 -c "Server=localhost;Database=wiresentry;Uid=root;Pwd=pass;"
```

## Building a Custom Scanner

Add a reference to `WireSentry.SDK.dll` and subclass `Scanner`:

```csharp
using WireSentry.SDK;

public class MyScanner : Scanner
{
    public MyScanner(IDebug debugger) : base(debugger) { }

    public override Guid Id => new Guid("...");
    public override string Author => "Your Name";
    public override string Name => "My Scanner";
    public override int Frequency => 30; // seconds

    public override IEnumerable<ScannerResult> Scan(IDataPacketCollection packets)
    {
        // Analyze packets and yield ScannerResult instances for detections
        yield break;
    }
}
```

Drop the compiled DLL into the scanners directory and Wire Sentry will load it automatically at startup.

## Project Structure

```
src/
  wiresentry/              # Core daemon (C#/Mono)
    WireSentry/            # Main executable and daemon
    WireSentry.SDK/        # SDK for building scanner modules
    WireSentry.Scanners.Common/  # Built-in scanner modules
  wiresentry-web/          # Web UI (Ruby on Rails)
data/
  schema.mysql             # Database schema
wiresentry.pdf             # Design document
```

## License

MIT License. See [LICENSE](LICENSE) for details.

---

> Why do network engineers make terrible comedians? Because their jokes always get dropped in transit.
