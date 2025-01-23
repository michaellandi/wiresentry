# Wire Sentry #
Copyright © 2013 Michael Landi 

---  

## About ##

Wire Sentry is a tool for analyzing network patterns to identify malicious activity.  It actively captures network traffic and compares the traffic against various scanners which attempt to identify these activities.  Wire Sentry is built upon a modular architecture in which attack patterns and scanners can be added to the application via dynamically loaded modules.  It is distributed with an SDK for creating these add-on modules in the hope that a large library of attack patterns can be created.

The application is currently coded in c# using the [mono][mono] framework.  Future portions of this application will use C and Ruby on Rails to add new features.

For more information, see [./wiresentry.pdf](wiresentry.pdf)

## License ##

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3.

This software is currently in its conception phase and is under active development.  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see [www.gnu.org/licenses/][gpl].

## Contact ##

For any bug reports or feature requests please contact me at mlandi[@]sourcesecure[.]net.

[gpl]:          http://www.gnu.org/licenses/
[mono]:         http://www.mono-project.com
