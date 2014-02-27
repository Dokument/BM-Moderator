BM-Moderator
============

BM-Moderator is an enhanced moderation utility for bitmessage.

Features:
- Works with multiple identities on a single client. Keeping permissions and settings seperated.
- Multi-tier permissions for enhanced control and moderation of your addresses.
- You can generate new addresses directly through bitmessage.
- Allows you to set an address as a mailing list or an echo address. 
-- Blacklisted (ban list) or Whitelisted (allowed list).



Setup Information
-----------------
Modify your Bitmessage keys.dat file to include the API information
Modify your Bitmessage keys.dat file to call bmModerator.py with "apinotifypath = /path/to/bmModerator/bmModerator.py"
- Don't forget to run "chmod 755 bmModerator.py" and "chmod +x bmModerator.py" if you do not compile it.
Run "bmModerator.py initalize" to access the initalization menu where you can:
- Set the API information
- Set the Owners Bitmessage address
- Generate a new address
- Send a message from the Owner Bitmessage address (another client) to one of the addresses on the bmModerator client
-- or generate a new address to have a message automatically sent to you!

NOTE: Make sure any existing addresses are not set as mailing lists in the official bitmessage client (or keys.dat)

All commands are sent in the subject line. Sending "--help" will return a list of available commands. If the command requires other data such as an address or text, put that in the message body. Below you will find the full help menu with a list of available commands and who can use those commands. 


This is very beta at the moment so if you like this project, check back for updates.

Thanks,
.dok



Help File
----------------------
User Commands
--setNick               Sets your nickname. Max 32 characters

Moderator Commands
--Help                  This help file is sent to you as a message
--clearNick             Send nickname to remove or send address to remove nickname from.
--addWhitelist          Adds a user to the whitelist for this address
--remWhitelist          Removes a user from the blacklist for this address
--addBlacklist          Adds a user to the blacklist for this address
--remBlacklist          Removes a user from the blacklist for this address
--inviteUser            Sends an invitation to whitelist users for this address
--addFilter             Adds the message body to filter list. Essentially a spam list. Be careful with this
--listFilters           Lists all filters and their ID numbers. Use this ID to remove individual filters
--clearFilter           Send filter ID in message body. If empty body, all filters are cleared

Admin Commands
--setLabel              Sets the label for the mailing list
--setMOTD               Sets the message of the day
--addModerator          Adds a moderator to this address
--remModerator          Removes a moderator from this address
--sendBroadcast         Sends whatever message you type out as a broadcast from this addres
--listModerators        Returns a list of Moderators and their information
--listUsers             Returns a list of all non-Admin/Moderator users and their information
--enable                Enables a disabled address
--disable               Disable address. Prevents users from using it. Mods and Admins still have access
--setMaxLength          Messages exceeding the max length are truncated. Set 0 for no max length
--getStats              UTC times. Set period in message "Day"/"Month"/"Year" or "All" for all stats
--getCommandHistory     Returns a command history list including who, what, and when

Admin+ Commands
--addAdmin              Adds an admin for this address
--remAdmin              Removed an admin from this address
--listAdmins            Returns a list of Admins and their information
--setBlacklist          Anyone can use this address except for Blacklisted users.
--setWhitelist          Only Whitelisted users (or Moderators/Admins) can use this address
--setMailingList        Makes this address send a broadcast of all messages it receives
--setEcho               Makes this address reply to all messages it receives

Owner Commands
--addAdmin+             Adds an admin for this address
--remAdmin+             Removed an admin from this address
--listAdmin+            Returns a list of Admins and their information
--generateNewAddress    Returns a new address that can be used. Defaults to Mailing List. Message is Label
--getInfo               Lists all information about every address on this server
