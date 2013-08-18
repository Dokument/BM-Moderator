BM-Moderator
============

BM-Moderator is an enhanced moderation utility for bitmessage.

Features:
- Works with multiple identities on a single client. Keeping permissions and settings seperated.
- Admin and moderator accounts allowing multiple layers of control through direct messages.
- Moderators can:
-- Add or remove addresses from the whitelist and blacklist for that mailing list.
-- Invite users to the mailing list. Users must accept to be whitelisted.
- Admins can:
-- Add or remove moderators and administrators. 
-- Send messages from the mailing list address - Not implemented yet
-- Send broadcasts from the mailing list address
-- Set the mailing list address as blacklist or whitelist
-- Change the label of the mailing list


Setup Information
-----------------
Modify your Bitmessage keys.dat file to include the API information
Modify your Bitmessage keys.dat file to call bmModerator.py with "apinotifypath = /path/to/bmModerator/bmModerator.py"
- Don't forget to run "chmod 755 bmModerator.py" and "chmod +x bmModerator.py" if you do not compile it.
Run Bitmessge and geneate an address, or addresses, to use as a mailing list
Run "bmModerator.py initalize"
- Enter in the relevant API information
- The first admin has to be manually added
-- add "DAV89w336ovy6BUJnfVRD5B9qipFbRgmr = admin" under the section for the mailing list (using their bm address not including "BM-")
- Send a message from the account you just added, to the mailing list, with the subject "--help" and you should get a response with the help file


All commands are sent in the subject line. Sending "--help" will return a list of available commands. If the command requires other data such as an address or text, put that in the message body.


This is very beta at the moment so if you like this project, check back for updates.

Thanks,

.dok
