#!/usr/bin/env python2.7
# Created by Adam Melton (.dok) referenceing https://bitmessage.org/wiki/API_Reference for API documentation
# Distributed under the MIT/X11 software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is an example of a moderator for PyBitmessage 0.3.5 mailing lists, by .dok (0.0.1)

import ConfigParser
import xmlrpclib
import hashlib
import getopt
import json
import sys
import time
from time import strftime, gmtime
import os

configFile = 'bmModerator.cfg'

#Begin BM address verifiication
###############################################################################################################

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def decodeBase58(string, alphabet=ALPHABET): #Taken from addresses.py
    """Decode a Base X encoded string into the number

    Arguments:
    - `string`: The encoded string
    - `alphabet`: The alphabet to use for encoding
    """
    base = len(alphabet)
    strlen = len(string)
    num = 0

    try:
        power = strlen - 1
        for char in string:
            num += alphabet.index(char) * (base ** power)
            power -= 1
    except:
        #character not found (like a space character or a 0)
        return 0
    return num

def decodeAddress(address):
    #returns true if valid, false if not a valid address. - taken from addresses.py

    address = str(address).strip()

    if address[:3].lower() == 'bm-':
        integer = decodeBase58(address[3:])
    else:
        integer = decodeBase58(address)
        
    if integer == 0:
        #print 'invalidcharacters' Removed because it appears in regular sendMessage
        return False
    #after converting to hex, the string will be prepended with a 0x and appended with a L
    hexdata = hex(integer)[2:-1]

    if len(hexdata) % 2 != 0:
        hexdata = '0' + hexdata

    #print 'hexdata', hexdata

    data = hexdata.decode('hex')
    checksum = data[-4:]

    sha = hashlib.new('sha512')
    sha.update(data[:-4])
    currentHash = sha.digest()
    #print 'sha after first hashing: ', sha.hexdigest()
    sha = hashlib.new('sha512')
    sha.update(currentHash)
    #print 'sha after second hashing: ', sha.hexdigest()

    if checksum != sha.digest()[0:4]:
        print '\n     Checksum Failed\n'
        return False

    return True

###############################################################################################################
#End BM address verifiication

 
#************************************* Begin File Lock *************************
class FileLockException(Exception):
    pass
 
class FileLock(object):
    """ A file locking mechanism that has context-manager support so 
        you can use it in a with statement. This should be relatively cross
        compatible as it doesn't rely on msvcrt or fcntl for the locking.
    """
 
    def __init__(self, file_name, timeout=10, delay=.05):
        """ Prepare the file locker. Specify the file to lock and optionally
            the maximum timeout and the delay between each attempt to lock.
        """
        self.is_locked = False
        self.lockfile = os.path.join(os.getcwd(), "%s.lock" % file_name)
        self.file_name = file_name
        self.timeout = timeout
        self.delay = delay
 
 
    def acquire(self):
        """ Acquire the lock, if possible. If the lock is in use, it check again
            every `wait` seconds. It does this until it either gets the lock or
            exceeds `timeout` number of seconds, in which case it throws 
            an exception.
        """
        start_time = time.time()
        while True:
            try:
                self.fd = os.open(self.lockfile, os.O_CREAT|os.O_EXCL|os.O_RDWR)
                break;
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise 
                if (time.time() - start_time) >= self.timeout:
                    raise FileLockException("Timeout occured.")
                time.sleep(self.delay)
        self.is_locked = True
 
 
    def release(self):
        """ Get rid of the lock by deleting the lockfile. 
            When working in a `with` statement, this gets automatically 
            called at the end.
        """
        if self.is_locked:
            os.close(self.fd)
            os.unlink(self.lockfile)
            self.is_locked = False
 
 
    def __enter__(self):
        """ Activated when used in the with statement. 
            Should automatically acquire a lock to be used in the with block.
        """
        if not self.is_locked:
            self.acquire()
        return self
 
 
    def __exit__(self, type, value, traceback):
        """ Activated at the end of the with statement.
            It automatically releases the lock if it isn't locked.
        """
        if self.is_locked:
            self.release()
 
 
    def __del__(self):
        """ Make sure that the FileLock instance doesn't leave a lockfile
            lying around.
        """
        self.release()
#************************************* End File Lock *************************

def initConfig(): #Initalizes the config file.
    global configFile
    config = ConfigParser.SafeConfigParser()

    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    try: #Try to see if the file already has data in it
        config.get('moderatorsettings', 'apiport')
    except:    #initalize config file
        config.add_section('moderatorsettings')        
        config.set('moderatorsettings', 'apiport', raw_input('Enter the apiPort:'))
        config.set('moderatorsettings', 'apiinterface', raw_input('Enter the apiInterface:'))
        config.set('moderatorsettings', 'apiusername', raw_input('Enter the apiUserName:'))
        config.set('moderatorsettings', 'apipassword', raw_input('Enter the apiPassword:'))
        
        with open(configFile, 'wb') as configfile:
            config.write(configfile)

        print 'Configuration File Initalized.'
        initConfig() #Call this procedure again since it is initalized

    api = xmlrpclib.ServerProxy(apiData()) #Connect to BitMessage using these api credentials stored in the config file
    jsonAddresses = json.loads(api.listAddresses())
    numAddresses = len(jsonAddresses['addresses']) #Number of addresses

    for addNum in range (0, numAddresses): #processes all of the addresses and gets the label for this address.
        label = jsonAddresses['addresses'][addNum]['label']
        address = jsonAddresses['addresses'][addNum]['address']
        
        config.add_section(address[3:])   
        config.set(address[3:], 'label', label) #sets the label as the label for the address by default
        config.set(address[3:], 'ismailinglist', 'false')
        config.set(address[3:], 'maxlength', '')
        config.set(address[3:], 'whiteorblacklist', 'blacklist')

    with open(configFile, 'wb') as configfile:
        config.write(configfile)

    print 'Configuration File Initalized.'

def apiData():
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    try: #checks to make sure that everyting is configured correctly.
        config.get('moderatorsettings', 'apiport')
        config.get('moderatorsettings', 'apiinterface')
        config.get('moderatorsettings', 'apiusername')
        config.get('moderatorsettings', 'apipassword')
    except:
        print 'Error accessing config file, please run "bmModerator initalize"'
        return ''

    config.read(configFile)#read again since changes have been made
    apiPort = int(config.get('moderatorsettings', 'apiport'))
    apiInterface = config.get('moderatorsettings', 'apiinterface')
    apiUsername = config.get('moderatorsettings', 'apiusername')
    apiPassword = config.get('moderatorsettings', 'apipassword')
    
    print '\n     API data successfully imported.\n'
        
    return "http://" + apiUsername + ":" + apiPassword + "@" + apiInterface+ ":" + str(apiPort) + "/" #Build the api credentials

'''def logCommand(recTime,bmAddress): #Removed until further notice
    global configFile
    config = ConfigParser.RawConfigParser()
    logFile = 'bmModLog.txt'
    config.read(configFile)

    try: #try to open the file
        config.get('EchoServer','processedTotal')
    except:# if it fails, then initialize the EchoLog.dat file since this is the first time running the program
        print 'Initializing EchoLog.dat'
        config.add_section('EchoServer')
        config.add_section('EchoLogs')
        
        config.set('EchoServer','versionNumber',str(versionNo))
        config.set('EchoServer','processedTotal','0')

    processedTotal = int(config.get('EchoServer','processedTotal'))
    processedTotal = processedTotal + 1
    
    config.set('EchoServer','processedTotal',str(processedTotal)) #echo count
    config.set('EchoLogs',str(processedTotal),str(recTime + "'" + bmAddress)) #message information
    
    with open(echoLogFile, 'wb') as configfile: #updates the total number of processed messages
        config.write(configfile)

    print 'Command successfully logged.'
    '''

def safeConfigGetBoolean(section,field):
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)
    
    try:
        return config.getboolean(section,field)
    except:
        return False

def safeConfigGetString(section,field):
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)
    
    try:
        return config.get(section,str(field))
    except:
        return ''

def isModerator(mlAddress,bmAddress):#Returns true if the address is a moderator of the specified mailing list
    if (safeConfigGetString(mlAddress[3:],bmAddress[3:]).lower() == 'moderator'):
        return True
    else:
        return False

def isAdmin(mlAddress,bmAddress):#Returns true if the address is a admin of the specified mailing list
    if (safeConfigGetString(mlAddress[3:],bmAddress[3:]).lower() == 'admin'):
        return True
    else:
        return False

def isPending(mlAddress,bmAddress):#Returns true if the address is pending an invite acception
    if (safeConfigGetString(mlAddress[3:],bmAddress[3:]).lower() == 'pending'):
        return True
    else:
        return False
    
def isMailingList(Address): #Addresses that are mailing lists return true, ones that are not return false
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    Address = Address [3:]
    
    try:
        return config.getboolean(Address,'ismailinglist')
    except:#Not found so initalize for this address
        config = ConfigParser.SafeConfigParser()
        with FileLock(configFile, timeout=3) as lock:
        #File Locked
            config.read(configFile)
        
        config.add_section(Address)
        config.set(Address, 'ismailinglist', 'false')
        config.set(Address, 'maxlength', '')
        config.set(Address, 'whiteorblacklist', 'blacklist')
        print 'Address added to config file. isMailingList set as FALSE by default'
        
        with open(configFile, 'wb') as configfile:
            config.write(configfile)
            
        return False


def chgModerator(addRem,mlAddress,bmAddress): #adds or removes moderator from mailing list
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    if (addRem == 'add'):
        config.set(mlAddress[3:],bmAddress,'moderator')
    elif (addRem == 'rem'):
        config.set(mlAddress[3:],bmAddress,'')

    with open(configFile, 'wb') as configfile: #Safe Config
        config.write(configfile)

def chgAdmin(addRem,mlAddress,bmAddress): #adds or removes admin from mailing list
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    if (addRem == 'add'):
        config.set(mlAddress[3:],bmAddress,'admin')
    elif (addRem == 'rem'):
        config.set(mlAddress[3:],bmAddress,'')

    with open(configFile, 'wb') as configfile: #Safe Config
        config.write(configfile)

def setMaxLength(mlAddress,length):
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    config.set(mlAddress[3:],'maxlength',str(length))

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)

def inviteUser(mlAddress,bmAddress):
    global configFile
    config = ConfigParser.SafeConfigParser()

    if ((isAdmin(mlAddress, bmAddress) == True) or (isModerator(mlAddress, bmAddress) == True)): #Could not change because they are an admin/moderator
        return False
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    config.set(mlAddress[3:],bmAddress[3:],'pending')

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)

    api = xmlrpclib.ServerProxy(apiData()) #Connect to BitMessage using these api credentials stored in the config file
    
    subject = '[BM-MODERATOR] You have been invited to join this mailing list.'
    message = """
This message was automatically sent to inform you that you have been invited to join this mailing list.
Please reply to this message with "Accept" as the subject and you will then be able to participate as a member of this mailing list.

Do not forget that you must subscribe to this address in order to receive broadcasts from the mailing list.

If you do not wish to join this mailing list or feel that it was sent by error, simply do not reply.
"""
    ackData = api.sendMessage(bmAddress, mlAddress, subject.encode('base64'),message.encode('base64'))

    return True

def setBlacklist(mlAddress): #sets the address as blacklist
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)
        
        
    config.set(mlAddress[3:], 'whiteorblacklist', 'blacklist')

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)
    return True

def setWhitelist(mlAddress): #sets the address as blacklist
    global configFile
    config = ConfigParser.SafeConfigParser()
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)
        
    config.set(mlAddress[3:], 'whiteorblacklist', 'whitelist')

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)

    return True

def whitelisted(addOrRem, mlAddress, bmAddress): #adds or removes a whitelisted user
    global configFile
    config = ConfigParser.SafeConfigParser()

    if ((isAdmin(mlAddress, bmAddress) == True) or (isModerator(mlAddress, bmAddress) == True)): #Could not change because they are an admin/moderator
        return False
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    if (addOrRem == 'add'):
        config.set(mlAddress[3:],bmAddress[3:],'whitelisted')
    elif (addOrRem == 'rem'):
        config.set(mlAddress[3:],bmAddress[3:],'nolongerwhitelisted')#Essentially removes whitelisted permissions

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)

    return True

def blacklisted(addOrRem, mlAddress, bmAddress): #adds or removes a blacklisted user
    global configFile
    config = ConfigParser.SafeConfigParser()

    if ((isAdmin(mlAddress, bmAddress) == True) or (isModerator(mlAddress, bmAddress) == True)): #Could not change because they are an admin/moderator
        return False
    
    with FileLock(configFile, timeout=3) as lock:
    #File Locked
        config.read(configFile)

    if (addOrRem == 'add'):
        config.set(mlAddress[3:],bmAddress[3:],'blacklisted')
    elif (addOrRem == 'rem'):
        config.set(mlAddress[3:],bmAddress[3:],'nolongerblacklisted')#Essentially removes whitelisted permissions

    with open(configFile, 'wb') as configfile: #Save Config
        config.write(configfile)

    return True

def isWhitelisted(mlAddress, bmAddress): #Checks if an address is whitelisted
    if (safeConfigGetString(mlAddress[3:],bmAddress[3:]).lower() == 'whitelisted'):
        return True
    else:
        return False

def isBlacklisted(mlAddress, bmAddress): #Checks if an address is blacklisted
    if (safeConfigGetString(mlAddress[3:],bmAddress[3:]).lower() == 'blacklisted'):
        return True
    else:
        return False

def processMsg():
    global configFile
    config = ConfigParser.SafeConfigParser()
    api = xmlrpclib.ServerProxy(apiData()) #Connect to BitMessage using these api credentials stored in the config file
    jsonAddresses = json.loads(api.listAddresses())
    numAddresses = len(jsonAddresses['addresses']) #Number of addresses

    inboxMessages = json.loads(api.getAllInboxMessages()) #Parse json data in to python data structure
    print 'Loaded all inbox messages for processing.'
    
    newestMessage = (len(inboxMessages['inboxMessages']) - 1) #Find the newest message
    
    fromAddress = inboxMessages['inboxMessages'][newestMessage]['fromAddress'] #Get the return address
    toAddress = inboxMessages['inboxMessages'][newestMessage]['toAddress'] #Get my address
    message = inboxMessages['inboxMessages'][newestMessage]['message'].decode('base64') #Gets the message sent by the user
    subject = inboxMessages['inboxMessages'][newestMessage]['subject'].decode('base64') #Gets the subject

    print 'Loaded and parsed data.'

    addLabel = '[' + safeConfigGetString(toAddress[3:],'label') + ']'

    subject = subject.lstrip() #Removes spaces and white space from beginning of subject. 
    message = message.lstrip() #Removes spaces and white space from beginning of message. 

    if ((isModerator(toAddress,fromAddress)== True) or (isAdmin(toAddress,fromAddress)) and (subject[:2] == "--")): #removes "BM- from address" and checks if a moderator or admin and if sending command
        #Begin moderator commands
        print 'Sender is a moderator or administrator.'
        if (subject[:6].lower() == "--help") or (subject[3:].lower() == "--h"):
            message = """
Help File
----------------------
Moderator Commands
--Help                  This help file is sent to you as a message
--addWhitelist          Adds a user to the whitelist for this address
--remWhitelist          Removes a user from the blacklist for this address
--addBlacklist          Adds a user to the blacklist for this address
--remBlacklist          Removes a user from the blacklist for this address
--inviteUser            Sends an invitation to whitelist users for this address.

Admin Commands
--setLabel              Sets the label for the mailing list. 
--addModerator          Adds a moderator to this address
--remModerator          Removes a moderator from this address
--addAdmin              Adds an admin for this address
--remAdmin              Removed an admin from this address
--sendMessage           Sends whatever message you type to the address at the beginning of the message
--sendBroadcast         Sends whatever message you type out as a broadcast from this address
--setBlacklist          Sets this address as a blacklist. Meaning anyone can use it except those blacklisted
--setWhitelist          Sets this address as a whitelist. Meaning only whitelisted users can participate
--setMaxLength          Messages exceeding the max length are truncated. Set no value for no max length

Send all commands as the subject and all relevant data as the message (such as an address to blacklist)

Example
----------------------
Subject:--addModerator
Message:BM-2DAV89w336ovy6BUJnfVRD5B9qipFbRgmr
----------------------

Other Information:
* Do note that all commands are logged so do not abuse your privileges.
* If your mailing list is set as a blacklist, then there is no purpose to have whitelisted users.
* All moderators and admins are whitelisted by default"""

        elif (subject[:14].lower() == "--addwhitelist"): #blacklists an address
            print '--addwhitelist'
            message = message.replace(" ", "") #Removes all spaces from message
            if message[:3].lower() == 'bm-': #Removes BM- from address
                message = message[3:]
            if (decodeAddress(message) == True): #if the address is valid, then add it to the blacklist for this mailing list. 
                if (whitelisted('add',toAddress,message) ==True):
                    message = str(message) + ' successfully added to the whitelist for ' + addLabel + ' ' + str(toAddress)
                else:
                    message = str(message) + ' could not be added to the whitelist for ' + addLabel + ' ' + str(toAddress)
            else:
                message = str(message) + ' is an invalid address and could not be whitelisted for ' + addLabel + ' ' + str(toAddress)
                
        elif (subject[:14].lower() == "--remwhitelist"): #blacklists an address
            print '--remwhitelist'
            message = message.replace(" ", "") #Removes all spaces from message
            if message[:3].lower() == 'bm-': #Removes BM- from address
                message = message[3:]
            if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                if (whitelisted('rem',toAddress,message) == True):
                    message = str(message) + ' successfully removed from the whitelist for ' + addLabel + ' ' + str(toAddress)
                else:
                    message = str(message) + ' could not be removed from the whitelist for ' + addLabel + ' ' + str(toAddress)
            else:
                message = str(message) + ' is an invalid address and could not be removed from the whitelist for ' + addLabel + ' ' + str(toAddress)
        elif (subject[:14].lower() == "--addblacklist"): #blacklists an address
            print '--addblacklist'
            message = message.replace(" ", "") #Removes all spaces from message
            if message[:3].lower() == 'bm-': #Removes BM- from address
                message = message[3:]
            if (decodeAddress(message) == True): #if the address is valid, then add it to the blacklist for this mailing list. 
                if (blacklisted('add',toAddress,message) == True):
                    message = str(message) + ' successfully added to the blacklist for ' + addLabel + ' ' + str(toAddress)
                else:
                    message = str(message) + ' could not be added to the blacklist for ' + addLabel + ' ' + str(toAddress)
            else:
                message = str(message) + ' is an invalid address and could not be blacklisted for ' + addLabel + ' ' + str(toAddress)
                
        elif (subject[:14].lower() == "--remblacklist"): #blacklists an address
            print '--remblacklist'
            message = message.replace(" ", "") #Removes all spaces from message
            if message[:3].lower() == 'bm-': #Removes BM- from address
                message = message[3:]
            if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                if (blacklisted('rem',toAddress,message) == True):
                    message = str(message) + ' successfully removed from the blacklist for ' + addLabel + ' ' + str(toAddress)
                else:
                    message = str(message) + ' could not be removed from the blacklist for ' + addLabel + ' ' + str(toAddress)
                    
            else:
                message = str(message) + ' is an invalid address and could not be removed from the blacklisted for ' + addLabel + ' ' + str(toAddress)
        elif (subject[:12].lower() == "--inviteuser"): #Invites a user to the mailing list
            print '--inviteuser'
            message = message.replace(" ", "") #Removes all spaces from message
            #if message[:3].lower() == 'bm-': #Removes BM- from address
                #message = message[3:]
            if (decodeAddress(message) == True): #if the address is valid, then send invite 
                if (inviteUser(toAddress,message) == True): #sends the invite to the user and adds pending to the config
                    message = str(message) + ' successfully invited to ' + addLabel + ' ' + str(toAddress)
                else:
                    message = str(message) + ' could not be invited to ' + addLabel + ' ' + str(toAddress)
            else:
                message = str(message) + ' is an invalid address and could not be invited to ' + addLabel + ' ' + str(toAddress)
        elif (isAdmin(toAddress,fromAddress)== True): #only runs if admin
            #Begin Admin commands
            
            print 'Command was not at moderator level, checking admin commands'
            if (subject[:10].lower() == "--setLabel"):

                with FileLock(configFile, timeout=3) as lock:
                #File Locked
                    config.read(configFile)

                config.set('moderatorsettings', toAddress[3:], message) #sets the label
                with open(configFile, 'wb') as configfile:
                    config.write(configfile)
                
            elif (subject[:14].lower() == "--addmoderator"):
                message = message.replace(" ", "") #Removes all spaces from message
                if message[:3].lower() == 'bm-': #Removes BM- from address
                    message = message[3:]
                if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                    chgModerator('add',toAddress,message)
                    ackData = api.sendMessage(message, toAddress, 'BM-Moderator'.encode('base64'), (fromAddress + ' made you a moderator of ' + addLabel + ' ' + toAddress + '\n\nReply to this message with --help as the subject line for a list of available commands').encode('base64'))
                    message = str(message) + ' successfully added as a moderator for ' + str(toAddress)
                else:
                    message = str(message) + ' is an invalid address and could not be added as a moderator for '+ addLabel + ' ' + str(toAddress)
                    
                    #message to new moderator fromAddress + ' made you a moderator of ' + mlAddress '. Send a message with the text --help or -h for a list of available commands.'
                    #message to sender 'You successfully addeded ' + theaddress + ' as a moderator.'
            
            elif (subject[:14].lower() == "--remmoderator"):
                message = message.replace(" ", "") #Removes all spaces from message
                if message[:3].lower() == 'bm-': #Removes BM- from address
                    message = message[3:]
                if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                    chgModerator('rem',toAddress,message)
                    ackData = api.sendMessage(message, toAddress, 'BM-Moderator'.encode('base64'), ('You have been removed from moderating '+ addLabel + ' '  + toAddress).encode('base64'))
                    message = str(message) + ' successfully removed as a moderator for ' + str(toAddress)
                else:
                    message = str(message) + ' is an invalid address and could not be removed as a moderator for '+ addLabel + ' '  + str(toAddress)
                    
                #Check if they were a moderator already
                # -if they wern't or false, then to sender  theaddress+ ' was already not a moderator'
            elif (subject[:10].lower() == "--addadmin"):
                message = message.replace(" ", "") #Removes all spaces from message
                if (message[3:]).lower() == 'bm-': #Removes BM- from address
                    message = message[3:]
                if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                    chgAdmin('add',toAddress,message)
                    message = str(message) + ' successfully added as an Admin for ' + str(toAddress)
                    ackData = api.sendMessage(message, toAddress, 'BM-Moderator'.encode('base64'), (fromAddress + ' made you an Admin of '+ addLabel + ' '  + toAddress + '\n\nReply to this message with --help as the subject line for a list of available commands').encode('base64'))
                else:
                    message = str(message) + ' is an invalid address and could not be added as an Admin for '+ addLabel + ' '  + str(toAddress)
                    
                    #message to new moderator fromAddress + ' made you a moderator of ' + mlAddress '. Send a message with the text --help or -h for a list of available commands.'
                    #message to sender 'You successfully addeded ' + theaddress + ' as a moderator.'
                
            elif (subject[:10].lower() == "--remadmin"):
                message = message.replace(" ", "") #Removes all spaces from message
                if message[:3].lower() == 'bm-': #Removes BM- from address
                    message = message[3:]
                if (decodeAddress(message) == True): #if the address is valid, then remove it to from blacklist for this mailing list. 
                    chgAdmin('rem',toAddress,message)
                    message = str(message) + ' successfully removed as an Admin for ' + str(toAddress)
                    ackData = api.sendMessage(message, toAddress, 'BM-Moderator'.encode('base64'), (fromAddress + ' removed you as an Admin of '+ addLabel + ' '  + toAddress).encode('base64'))
                else:
                    message = str(message) + ' is an invalid address and could not be removed as an Admin for '+ addLabel + ' '  + str(toAddress)
#            elif (subject[:13].lower() == "--sendmessage"):
#                subject = '[MODERATOR]'.encode('base64')
#                message = message.encode('base64')
#                Add code to get address from beginning of message
#                ackData = api.sendMessage(fromAddress, toAddress, subject, message)
#                sys.exit()
#                allows admins to send messages on behalf of the mailing list address
            
            elif (subject[:15].lower() == "--sendbroadcast"):
                api.sendBroadcast(toAddress,('BM-Moderator').encode('base64'),message.encode('base64')) #Build the message and send it
                sys.exit()
                #allows moderator to send broadcasts on behalf of the broacast/mailing list address

            elif (subject[:14].lower() == "--setblacklist"):
                if (setBlacklist(toAddress) == True): #sets the mailing list address as blacklisted
                    message = config.get(toAddress[3:],'label') + ' ' + toAddress  + ' is now set to Blacklist.'
                else:
                    message = config.get(toAddress[3:],'label') + ' ' + toAddress  + ' could not be set to Blacklist.'                    
                
            elif (subject[:14].lower() == "--setwhitelist"):
                if (setWhitelist(toAddress) == True): #Sets the mailing list address as whitelisted
                    message = config.get(toAddress[3:],'label') + ' ' + toAddress  + ' is now set to Whitelist.'
                else:
                    message = config.get(toAddress[3:],'label') + ' ' + toAddress  + ' could not be set to Whitelist.'
                
            elif (subject[:14].lower() == "--setMaxLength"):
                setMaxLength(toAddress, int(message)) #Converts to int so that if there is an error, it faults here and not when trying to load the length
                message = str(message)  + ' is now set the maximum message length for '+ config.get(toAddress[3:],'label') + ' '  + str(toAddress)
            else: #valid admin command not found
                message = subject + ' is an invalid command. Send a message with "--help" as the subject to receive a list of available commands'

        else: #valid moderator command not found
            message = subject + ' is an invalid command or you do not have permission to use this command. Send a message with "--help" as the subject to receive a list of available commands'                

        subject = '[BM-MODERATOR]'.encode('base64')
        message = message.encode('base64')
        ackData = api.sendMessage(fromAddress, toAddress, subject, message)#Sends a message back to the person issuing the command to alert them that the command was executed or not.

        #print 'Begin logging Command'
        #logCommand(strftime("%Y_%m_%d'%H_%M_%S",timeStamp), replyAddress) #Logs command to file 
            
    elif (isPending(toAddress,fromAddress) == True): #Person was sent an invite and we are currently pending their acception
        whitelisted('add',toAddress,fromAddress) #adds them as a whitelisted user
        print 'User added to whitelist'
        
    elif (isMailingList(toAddress) == True):#Elif it is a mailing list
        print 'Processing mailing list request'
        with FileLock(configFile, timeout=3) as lock:
        #File Locked
            config.read(configFile)

        if (safeConfigGetString(toAddress[3:],'whiteorblacklist') == 'whitelist'): #check if the mailing list is a whitelist, if so, only allow whitelisted addresses
            print 'Address is whitelisted'
            
            if(isWhitelisted(toAddress,fromAddress) == False and isModerator(toAddress,fromAddress) == False and isAdmin(toAddress,fromAddress) == False):
                print 'User not whitelisted, exiting'
                sys.exit() #Since they are not whitelisted, exit and do nothing.
        elif (safeConfigGetString(toAddress[3:],'whiteorblacklist') == 'blacklist'):#check if mailing list is blacklisted, if so, deny blacklisted addresses
            print 'Address is blacklisted'

            if(isBlacklisted(toAddress,fromAddress) == True):
                print 'User is blacklisted, exiting'
                sys.exit() #Since they are blacklisted, exit and do nothing.
        if (str((subject[:4]).lower()) == 're: '):
            subject = subject[4:] #Removes re: or RE: from subject
        if ( str(subject[:(len(addLabel)+2)]).lower() != str(addLabel)): #If it is equal then there is nothing to change with the subject
            subject = (addLabel + subject).encode('base64') #Set the new subject

        maxLength = safeConfigGetString(toAddress[3:],'maxlength')
        
        if (str(maxLength) != ''): #If it is null then no maximum length. 
            if (len(message) > int(maxLength)): #Truncates the message if it is too long
                message = (message[:int(maxLength)] + '... Truncated.\n')
                
        if (len(subject) > int(500)): #Truncates the subject if over 500 characters
                subject = (subject[:int(500)] + '... Truncated.\n')
                
        message = strftime("%a, %Y-%m-%d %H:%M:%S UTC",gmtime()) + '   Message ostensibly from ' + fromAddress + ':\n\n' + message #adds the message ostensibly from text.

        print 'Message built, ready to send. Sending...'
        
        message = message.encode('base64') #Encode the message.
        api.sendBroadcast(toAddress,subject,message) #Build the message and send it
        print 'Sent.'



def main():
    arg = sys.argv[1]
        
    if arg == "startingUp":
        sys.exit() #No action
                                              
    elif arg == "newMessage":
        processMsg() #Start Moderation
        print 'Done.'
        sys.exit() #Done, exit
        
    elif arg == "newBroadcast":
        sys.exit()#No action
                                              
    elif arg == "initalize":
        initConfig()
        sys.exit()#No action

    else:
        #assert False, "unhandled option"
        sys.exit() #Not a relevant argument, exit
        
if __name__ =="__main__":
    main()
