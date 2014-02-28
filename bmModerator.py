#!/usr/bin/env python

# Created by Adam Melton (.dok) referenceing https://bitmessage.org/wiki/API_Reference for API documentation
# Distributed under the MIT/X11 software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import sys
import os
import json
import getopt
import xmlrpclib
import hashlib
from time import strftime,gmtime
import sqlite3 as lite

database = 'bmModerator.db'

# Begin BM address verifiication
# ##############################################################################################################

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
        return 0
    return num

def decodeAddress(address):
    try:
        # Returns true if valid, false if not a valid address. - taken from addresses.py
        address = str(address).strip()

        if address[:3].lower() == 'bm-':
            integer = decodeBase58(address[3:])
        else:
            integer = decodeBase58(address)
            
        if integer == 0:
            return False
        
        hexdata = hex(integer)[2:-1]

        if len(hexdata) % 2 != 0:
            hexdata = '0' + hexdata

        data = hexdata.decode('hex')
        checksum = data[-4:]

        sha = hashlib.new('sha512')
        sha.update(data[:-4])
        currentHash = sha.digest()

        sha = hashlib.new('sha512')
        sha.update(currentHash)

        if checksum != sha.digest()[0:4]:
            print '\n     Checksum Failed\n'
            return False

        return True
    except Exception as e:
        print 'ERROR decoding address:',e
    return False

# ##############################################################################################################
# End BM address verifiication

def create_db():
    try:
        os.remove(database)
        time.sleep(1)
    except Exception as e:
        pass
    
    try:
        con = lite.connect(database) 
        cur = con.cursor()

        cur.execute("CREATE TABLE api_config(id INTEGER PRIMARY KEY, api_port TEXT,api_address TEXT,api_username TEXT, api_password TEXT, global_admin_bm_address TEXT)")
        cur.execute("INSERT INTO api_config VALUES (?,?,?,?,?,?)",('0','8442','127.0.0.1','apiUser','apiPass',' '))
        
        cur.execute("CREATE TABLE bm_addresses_config(id INTEGER PRIMARY KEY, bm_address TEXT, label TEXT, enabled TEXT, motd TEXT,whitelisted TEXT, max_msg_length INT, echo_address TEXT)")

        cur.execute("CREATE TABLE users_config(id INTEGER PRIMARY KEY, ident_bm_address TEXT, usr_bm_address TEXT, nickname TEXT, admin_moderator TEXT, whitelisted_blacklisted TEXT)")

        cur.execute("CREATE TABLE command_history(id INTEGER PRIMARY KEY, ident_bm_address TEXT, usr_bm_address TEXT, date_time TEXT, command TEXT, message_snippet TEXT)")
        
        cur.execute("CREATE TABLE stats(id INTEGER PRIMARY KEY, date_day TEXT, bm_address TEXT, num_sent_broadcasts INT, num_sent_messages INT)")

        cur.execute("CREATE TABLE filter(id INTEGER PRIMARY KEY, banned_text TEXT)")

        con.commit()
        cur.close()

    except Exception as e:
        print 'Failed creating database (%s):%s' % (database,e)
'''
def create_add_address_table(con,ident_address):    
    try:        
        cur = con.cursor()
        #Select from table, if fail the create
        
        cur.execute("CREATE TABLE IF NOT EXISTS ?(id INTEGER PRIMARY KEY, bm_address TEXT, nickname TEXT, admin_moderator TEXT, whitelisted_blacklisted TEXT)",(ident_address,))
        cur.execute("INSERT INTO bm_addresses_config VALUES(?,?,?,?,?,?,?,?)",(None,bm_address,label,enabled,motd,whitelisted,max_msg_length,echo_address))
        
        con.commit()
        return True
    except Exception as e:
        print 'Failed',e
        return False
'''

def api_data(con):
    # Returns API url string
    cur = con.cursor()
    cur.execute("SELECT api_port,api_address,api_username,api_password FROM api_config")
    temp = cur.fetchone()
    cur.close()

    if temp == None or temp == '':
        print 'Data Error with API Table. Blank.'
        return
    else:
        api_port,api_address,api_username,api_password = temp
        
    return "http://" + str(api_username) + ":" + str(api_password) + "@" + str(api_address)+ ":" + str(api_port) + "/"

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def format_address(address_to_format):
    # Removes BM- prefix if it exists
    if address_to_format[:3].lower() == 'bm-':
        address_to_format = address_to_format[3:]
    return address_to_format

def is_global_admin(con,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    
    cur = con.cursor()
    cur.execute("SELECT global_admin_bm_address FROM api_config WHERE id=?",('0',))
    temp = cur.fetchone()
    cur.close()

    if temp == None or temp == '':
        print 'Data Error with API Table. Blank.'
        return False
    else:
        global_admin_bm_address = str(temp[0])

    global_admin_bm_address = format_address(global_admin_bm_address)

    if usr_bm_address == global_admin_bm_address:
        return True
    else:
        return False

def is_adminPlus(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)

    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address,admin_moderator,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address,])
    while True:
        temp = cur.fetchone()

        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address,admin_moderator,whitelisted_blacklisted = temp

            if ident_bm_address == ident_address:
                if whitelisted_blacklisted == 'blacklisted':
                    return False
                elif admin_moderator == 'admin+':
                    return True
                else:
                    return False

def is_admin(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)

    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address,admin_moderator,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address,])
    while True:
        temp = cur.fetchone()

        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address,admin_moderator,whitelisted_blacklisted = temp

            if ident_bm_address == ident_address:
                if whitelisted_blacklisted == 'blacklisted':
                    return False
                elif admin_moderator == 'admin':
                    return True
                else:
                    return False

def is_moderator(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)

    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address,admin_moderator,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address,])
    while True:
        temp = cur.fetchone()

        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address,admin_moderator,whitelisted_blacklisted = temp

            if ident_bm_address == ident_address:
                if whitelisted_blacklisted == 'blacklisted':
                    return False
                elif admin_moderator == 'moderator':
                    return True
                else:
                    return False

def is_whitelisted(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address,])
    while True:
        temp = cur.fetchone()

        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address,whitelisted_blacklisted = temp

            if ident_bm_address == ident_address:
                if whitelisted_blacklisted == 'whitelisted':
                    return True
                else:
                    return False

def is_blacklisted(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address,])
    while True:
        temp = cur.fetchone()
        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address,whitelisted_blacklisted = temp

            if ident_bm_address == ident_address:
                if whitelisted_blacklisted == 'blacklisted':
                    return True
                else:
                    return False

def help_file():
    message = """Help File
----------------------
User Commands
--setNick               Sets your nickname. Max 32 characters

Moderator Commands
--Help                  This help file is sent to you as a message
--clearNick             Send nickname to remove or send address to remove nickname from.
--addWhitelist          Adds a user to the whitelist for this address
--remWhitelist          Removes a user from the whitelist for this address
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

Send all commands as the subject and all relevant data as the message (such as an address to blacklist)

Example
----------------------
Subject = "--addModerator"
Message = "BM-2DAV89w336ovy6BUJnfVRD5B9qipFbRgmr"
----------------------

Other Information:
* Do note that all commands are logged so do not abuse your privileges."""

    return message
    
def is_command(text_string):
    # Returns true if the string is a command
    command_list = ['--setNick','--setNickname','--Help','--clearNick','--addWhitelist','--remWhitelist','--addBlacklist','--remBlacklist','--inviteUser','--addFilter',
                    '--listFilters','--clearFilter','--setLabel','--setMOTD','--addModerator','--remModerator','--addAdmin','--remAdmin','--listAdmins',
                    '--sendBroadcast','--listModerators','--listUsers','--setMailingList','--setEcho','--setBlacklist','--setWhitelist','--setMaxLength',
                    'enable','disable','--generateNewAddress','--getStats','--getCommandHistory','--getInfo','--addAdmin+','--remAdmin+','--listAdmin+']

    # Possible Future Commands
    # Use API to verify address
    # Set address difficulty on creation or after creation
    # Ability to batch whitelist/blacklist/etc addresses? Reason not to, mass confirmation messages
    # Set max difficulty to send message, probably should be hard coded at least
    # TODO, don't allow moderators to perform actions on admins/admin+'s, etc

    for command in command_list:
        if command.lower() in text_string.lower():
            return True

    return False

def getInfo(con):
    try:
        cur = con.cursor()
        date_time = strftime("%Y-%m-%d:%H",gmtime())
        message = '%s Server Information' % date_time
        message += ln_brk() + 50*"-" + ln_brk(2)
        
        cur.execute("SELECT id,bm_address FROM bm_addresses_config")
        addressList = []
        while True:
            temp = cur.fetchone()
            if temp == None or temp == '':
                break
            else:
                addressList.append(temp[1])

        for address in addressList:
            label,enabled,motd,whitelisted,max_msg_length,echo_address = get_bm_ident_info(con,address)

            if enabled == 'enabled':
                enabled_result = 'True'
            else:
                enabled_result = 'False'

            if echo_address == 'false':
                echo_address_result = 'Mailing List'
            else:
                echo_address_result = 'Echo Address'

            if whitelisted == 'false':
                whitelisted_result = 'False'
            else:
                whitelisted_result = 'True'

            if max_msg_length == '0':
                max_msg_length_result = 'No Maximum'
            else:
                max_msg_length_result = str(max_msg_length)
            
            message += 'Address: %s' % str(address)
            message += 'Label: %s' % label + ln_brk()
            message += 'Enabled: %s' % enabled_result + ln_brk()
            message += 'Type: %s' % echo_address_result + ln_brk()
            message += 'Whitelisted: %s' % whitelisted_result + ln_brk()
            message += 'Max Length: %s' % max_msg_length + ln_brk()
            message += 'MOTD: %s' % motd + ln_brk()
            message += ln_brk() 
            message += listAdminPlus(con,address) + ln_brk(2)
            message += listAdmins(con,address) + ln_brk(2)
            message += listModerators(con,address) + ln_brk(2)
            message += listUsers(con,address)
            message += ln_brk(2)
            message += getStats(con,address,'')
            message += ln_brk(2)
            message += getCommandHistory(con,address)
            
            message += ln_brk(2) + 50*"#" + ln_brk(2)
            
        message += '----- Global -----' + ln_brk()
        message += listFilters(con)
            
        return message
    except Exception as e:
        print 'getInfo ERROR: ',e
        return ''

def get_bm_ident_info(con,ident_address):
    # Returns information about a bm address (an identity)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    
    cur.execute("SELECT label,enabled,motd,whitelisted,max_msg_length,echo_address FROM bm_addresses_config WHERE bm_address=?",[ident_address,])
    temp = cur.fetchone()

    if temp == None or temp == '':
        cur.execute("INSERT INTO bm_addresses_config VALUES(?,?,?,?,?,?,?,?)",(None,ident_address,'no label','enabled','','false','0','false'))
        con.commit()

        label,enabled,motd,whitelisted,max_msg_length,echo_address = ('no label','enabled','','false','0','false')
    else:
        label,enabled,motd,whitelisted,max_msg_length,echo_address = temp

    cur.close
    return label,enabled,motd,whitelisted,max_msg_length,echo_address

def banned_text(con,string_text):
    # Returns True if passed text is in the filter table
    cur = con.cursor()
    cur.execute("SELECT banned_text FROM filter")
    temp = cur.fetchone()
    while True:
        if temp == None or temp == '':
            break
        else:
            filtered_text = str(temp)

            if (filtered_text in string_text):
                cur.close()
                return True
    cur.close()
    return False

def check_if_new_msg(con):
    # Returns true if there are messages in the inbox
    apiurl = api_data(con)
    if not apiurl: return
    api = xmlrpclib.ServerProxy(apiurl)
    inboxMessages = json.loads(api.getAllInboxMessages())
    numMessages = len(inboxMessages['inboxMessages'])
    return numMessages != 0

def process_new_message(con):
    try:
        apiurl = api_data(con)
        if not apiurl: return
        api = xmlrpclib.ServerProxy(apiurl)
        inboxMessages = json.loads(api.getAllInboxMessages())

        oldesMessage = 0
        
        fromAddress = str(inboxMessages['inboxMessages'][oldesMessage]['fromAddress'])
        toAddress = str(inboxMessages['inboxMessages'][oldesMessage]['toAddress'])
        message = str(inboxMessages['inboxMessages'][oldesMessage]['message'].decode('base64'))
        subject = str(inboxMessages['inboxMessages'][oldesMessage]['subject'].decode('base64'))

        # Delete messages 
        msgId = inboxMessages['inboxMessages'][oldesMessage]['msgid']
        api.trashMessage(msgId)
        #sys.exit() # Temporary, used for dev
        
        if banned_text(con,subject + " " + message):
            print 'subject/message contains banned text'
            return None
        else: 
            toAddress = format_address(toAddress)
            fromAddress = format_address(fromAddress)
            return toAddress,fromAddress,message,subject

    except Exception as e:
        print 'process_new_message ERROR: ',e
        return None
        
def is_address(bm_address):
    return decodeAddress(bm_address)

def nick_taken(con,ident_address,nickname):
    # Returns True if a nickname is already taken
    cur = con.cursor()
    cur.execute("SELECT id,ident_bm_address FROM users_config WHERE nickname=?",[str(nickname),])
    while True:
        temp = cur.fetchone()
        if temp == None or temp == '':
            return False
        else:
            id_num,ident_bm_address = temp
            
            if ident_bm_address == ident_address:
                return True

def generateAddress(con,label=None):
    apiurl = api_data(con)
    if not apiurl: return
    api = xmlrpclib.ServerProxy(apiurl)
    if label is None: label = 'bmModerator'
    label = label.encode('base64')

    try:
        generatedAddress = api.createRandomAddress(label)
        generatedAddress = format_address(generatedAddress)
        return generatedAddress
    except Exception as e:
        print 'generateAddress ERROR: ',e
        return None

def initalize_user(con,ident_bm_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_bm_address = format_address(ident_bm_address)
    
    cur = con.cursor()
    cur.execute("INSERT INTO users_config VALUES(?,?,?,?,?,?)",(None,ident_bm_address,usr_bm_address,'','',''))
    con.commit()
    
    cur.execute("SELECT id,ident_bm_address FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
    while True:
        temp = cur.fetchone()

        if temp == None or temp == '':
            print 'initalize_user ERROR'
            break
        else:
            id_num,ident_address = temp

            if ident_address == ident_bm_address:
                return id_num

def setNick(con,ident_address,usr_bm_address,nickname):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if (len(nickname) <= 32):
        if (not nick_taken(con,ident_address,nickname) or is_moderator(con,usr_bm_address) or is_admin(con,usr_bm_address) or is_global_admin(con,usr_bm_address)): #If not taken and not an admin/global_admin
            cur.execute("SELECT id,ident_bm_address FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
            while True:
                temp = cur.fetchone()

                if temp == None or temp == '':
                    id_num = initalize_user(con,ident_address,usr_bm_address)               
                    cur.execute("UPDATE users_config SET nickname=? WHERE id=?",[nickname,id_num])
                    con.commit
                    break
                    
                else:
                    id_num,ident = temp

                    if ident == ident_address:              
                        cur.execute("UPDATE users_config SET nickname=? WHERE id=?",[nickname,id_num])
                        con.commit
                        break
                         
            new_message = 'Nickname successfully changed to (%s).' % str(nickname)
        else:
            new_message = 'Nickname already taken.'
    else:
        new_message = 'Nickname too long. Maximum Nickname Size: 32 Characters'
    return new_message

def clearNick(con,ident_address,nick_or_address):
    ident_address = format_address(ident_address)
        
    cur = con.cursor()
    
    if is_address(nick_or_address):
        nick_or_address = format_address(nick_or_address)
        cur.execute("SELECT id,ident_bm_address,nickname FROM users_config WHERE usr_bm_address=?",[nick_or_address])
        while True:
            temp = cur.fetchone()
            if temp == None or temp == '':
                new_message = 'No nickname found for user (%s).' % nick_or_address
                break
                
            else:
                id_num,ident_bm_address,nickname = temp

                if ident_bm_address == ident_address:              
                    cur.execute("UPDATE users_config SET nickname=? WHERE id=?",['',id_num])
                    con.commit
                    new_message = 'Nickname (%s) successfully removed for user (%s).' % (nickname,nick_or_address)
                    break
        
    else:
        cur.execute("SELECT id,ident_bm_address,usr_bm_address FROM users_config WHERE nickname=?",[nick_or_address])
        while True:
            temp = cur.fetchone()
            if temp == None or temp == '':
                new_message = 'No users found with nickname (%s).' % nick_or_address
                break
                
            else:
                id_num,ident_bm_address,usr_bm_address = temp

                if ident_bm_address == ident_address:              
                    cur.execute("UPDATE users_config SET nickname=? WHERE id=?",['',id_num])
                    con.commit
                    new_message = 'Nickname (%s) successfully removed for user (%s).' % (nick_or_address,usr_bm_address)
                    break

    return new_message

def addWhiteList(con,ident_address,usr_bm_address,new_subject):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['whitelisted',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,whitelisted_blacklisted = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['whitelisted',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully whitelisted. An automatic message was sent to alert them.' % usr_bm_address
        tmp_msg = 'This address has been whitelisted for: %s' % ident_address
        send_message(con,usr_bm_address,ident_address,new_subject,tmp_msg)
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def remWhiteList(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,whitelisted_blacklisted = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully removed from whitelist.' % usr_bm_address
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def addBlackList(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['blacklisted',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,whitelisted_blacklisted = temp

                if ident_bm_address == ident_address:
                    cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['blacklisted',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully blacklisted.' % usr_bm_address
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def remBlackList(con,ident_address,usr_bm_address):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,whitelisted_blacklisted = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully removed from blacklist.' % usr_bm_address
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def inviteUser(con,ident_address,usr_bm_address,new_subject):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['invited',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,whitelisted_blacklisted = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET whitelisted_blacklisted=? WHERE id=?",['invited',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully invited to join this address.' % usr_bm_address
        tmp_msg = 'This address has been invited by BM-%s to join: BM-%s. Respond with "Accept" as the subject to accept this invitation.' % (usr_bm_address,ident_address)
        send_message(con,usr_bm_address,ident_address,new_subject,tmp_msg)
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def addModerator(con,ident_address,usr_bm_address,new_subject):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,admin_moderator FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['moderator',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,admin_moderator = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['moderator',id_num])
                    con.commit
                    break
                    
        new_message = 'BM-%s successfully added to moderators. A notice was automatically sent to notify them.' % usr_bm_address
        tmp_msg = 'This address has been added to the Moderator group by BM-%s for: BM-%s. Reply with the subject "--Help" for a list of commands.' % (usr_bm_address,ident_address)
        send_message(con,usr_bm_address,ident_address,new_subject,tmp_msg)
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % usr_bm_address

    return new_message

def addAdmin(con,ident_address,usr_bm_address,new_subject): 
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()    
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,admin_moderator FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['admin',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,admin_moderator = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['admin',id_num])
                    con.commit
                    break
        
        new_message = 'BM-%s successfully added to admins. A notice was automatically sent to notify them.' % usr_bm_address
        tmp_msg = 'This address has been added to the Admin group by BM-%s for: BM-%s. Reply with the subject "--Help" for a list of commands.' % (usr_bm_address,ident_address)
        send_message(con,usr_bm_address,ident_address,new_subject,tmp_msg)
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % bm_address

    return new_message

def addAdminPlus(con,ident_address,usr_bm_address,new_subject): 
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()    
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,admin_moderator FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['admin+',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,admin_moderator = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['admin+',id_num])
                    con.commit
                    break
        
        new_message = 'BM-%s successfully added to Admin+. A notice was automatically sent to notify them.' % usr_bm_address
        tmp_msg = 'This address has been added to the Admin+ group by BM-%s for: BM-%s. Reply with the subject "--Help" for a list of commands.' % (usr_bm_address,ident_address)
        send_message(con,usr_bm_address,ident_address,new_subject,tmp_msg)
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % bm_address

    return new_message

# Used to remove privileges for moderators/admins/admin+s
def remPrivilege(con,ident_address,usr_bm_address): 
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    cur = con.cursor()
    if is_address(usr_bm_address):
        cur.execute("SELECT id,ident_bm_address,admin_moderator FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                id_num = initalize_user(con,ident_address,usr_bm_address)               
                cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['',id_num])
                con.commit
                break
            else:
                id_num,ident_bm_address,admin_moderator = temp

                if ident_bm_address == ident_address:               
                    cur.execute("UPDATE users_config SET admin_moderator=? WHERE id=?",['',id_num])
                    con.commit
                    break
                    
        
        new_message = 'Successfully removed privileges from address: BM-%s' % bm_address
    else:
        new_message = 'Invalid Bitmessage address: BM-%s' % bm_address

    return new_message

def ln_brk(how_many=1):
    return "\n"*how_many

def listAdminPlus(con,ident_address):
    try:
        ident_address = format_address(ident_address)
        new_message = '----- List of Administrators -----'
        cur = con.cursor()
        cur.execute("SELECT usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted FROM users_config WHERE ident_bm_address=?",[ident_address,])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                new_message += ln_brk() + '----- End -----'
                break
            else:
                usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted = temp

                if admin_moderator == 'admin+':
                    whitelisted = 'False'
                    blacklisted = 'False'
                    
                    if whitelisted_blacklisted == 'blacklisted':
                        blacklisted = 'True'
                    elif whitelisted_blacklisted == 'whitelisted':
                        whitelisted = 'True'

                    new_message += ln_brk() + 'BM-%s   Whitelisted:%s   Blacklisted:%s   Nickname:%s' % (usr_bm_address,whitelisted,blacklisted,nickname)
        return new_message
    except Exception as e:
        print 'listAdmin+ ERROR: ',e
        return ''

def listAdmins(con,ident_address):
    try:
        ident_address = format_address(ident_address)
        new_message = '----- List of Administrators -----'
        cur = con.cursor()
        cur.execute("SELECT usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted FROM users_config WHERE ident_bm_address=?",[ident_address,])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                new_message += ln_brk() + '----- End -----'
                break
            else:
                usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted = temp

                if admin_moderator == 'admin':
                    whitelisted = 'False'
                    blacklisted = 'False'
                    
                    if whitelisted_blacklisted == 'blacklisted':
                        blacklisted = 'True'
                    elif whitelisted_blacklisted == 'whitelisted':
                        whitelisted = 'True'

                    new_message += ln_brk() + 'BM-%s   Whitelisted:%s   Blacklisted:%s   Nickname:%s' % (usr_bm_address,whitelisted,blacklisted,nickname)
        return new_message
    except Exception as e:
        print 'listAdmins ERROR: ',e
        return ''

def listModerators(con,ident_address):
    try:
        ident_address = format_address(ident_address)
        new_message = '----- List of Moderators -----'
        cur = con.cursor()
        cur.execute("SELECT usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted FROM users_config WHERE ident_bm_address=?",[ident_address,])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                new_message += ln_brk() + '----- End -----'
                break
            else:
                usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted = temp

                if admin_moderator == 'moderator':
                    whitelisted = 'False'
                    blacklisted = 'False'
                    
                    if whitelisted_blacklisted == 'blacklisted':
                        blacklisted = 'True'
                    elif whitelisted_blacklisted == 'whitelisted':
                        whitelisted = 'True'

                    new_message += ln_brk() + 'BM-%s   Whitelisted:%s   Blacklisted:%s   Nickname:%s' % (usr_bm_address,whitelisted,blacklisted,nickname)
        return new_message
    except Exception as e:
        print 'listModerators ERROR: ',e
        return ''
        
def listUsers(con,ident_address):
    try:
        ident_address = format_address(ident_address)
        new_message = '----- List of Users -----'
        cur = con.cursor()
        cur.execute("SELECT usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted FROM users_config WHERE ident_bm_address=?",[ident_address,])
        while True:
            temp = cur.fetchone()

            if temp == None or temp == '':
                new_message += ln_brk() + '----- End -----'
                break
            else:
                usr_bm_address,nickname,admin_moderator,whitelisted_blacklisted = temp

                # List everything except admins or moderators, global user (owner) is in a different table.
                if admin_moderator != 'admin' and admin_moderator != 'moderator':
                    whitelisted = 'False'
                    blacklisted = 'False'
                    
                    if whitelisted_blacklisted == 'blacklisted':
                        blacklisted = 'True'
                    elif whitelisted_blacklisted == 'whitelisted':
                        whitelisted = 'True'

                    new_message += ln_brk() + 'BM-%s   Whitelisted:%s   Blacklisted:%s   Nickname:%s' % (usr_bm_address,whitelisted,blacklisted,nickname)
        return new_message
    except Exception as e:
        print 'listUsers ERROR: ',e
        return ''

def listFilters(con):
    cur = con.cursor()
    
    new_message = '----- Filter List -----' + ln_brk()
    cur.execute('SELECT id,banned_text FROM filter')
    while True:
        temp = cur.fetchone()
        if temp == None or temp == '':
            new_message += '----- End -----'
            break
        else:
            id_num,banned_text = temp

        new_message += 'Filter ID: %s' % id_num + ln_brk()
        new_message += 'Filter Length: %s characters' % str(len(banned_text)) + ln_brk()
        new_message += 'Filter Snippet [%s...]' % str(banned_text)[:64] + ln_brk()

        new_message += ln_brk(2)

    return new_message
        
def getStats(con,ident_address,time_period):
    cur = con.cursor()
    
    time_period = time_period.strip()
    time_period = time_period.lower()
    
    if time_period == 'day':
        date_time = strftime("%Y-%m-%d",gmtime())
    elif time_period == 'month':
        date_time = strftime("%Y-%m",gmtime())
    elif time_period == 'year':
        date_time = strftime("%Y",gmtime())
    else:
        date_time = 'forever'
        
    total_messages = 0
    total_broadcasts = 0

    new_message = '----- Message and Broadcast Statistics for %s UTC/GMT -----' % date_time
        
    cur.execute('SELECT date_day,num_sent_broadcasts,num_sent_messages FROM stats WHERE bm_address=?' ,[ident_address,])
    while True:
        temp = cur.fetchone()
        if temp == None or temp == '':
            new_message += ln_brk() + '----- Total Messages:%s | Total Broadcasts:%s -----' % (str(total_messages),str(total_broadcasts))
            break
        else:
            date_day,num_sent_broadcasts,num_sent_messages = temp
            if (str(date_day[:len(date_time)]) == date_time) or (date_time == 'forever'):
                total_messages += num_sent_messages
                total_broadcasts += num_sent_broadcasts
                new_message += ln_brk() + '%s | Messages:%s | Broadcasts:%s' % (str(date_day),str(num_sent_broadcasts),str(num_sent_messages))
    return new_message

def getCommandHistory(con,ident_address):
    cur = con.cursor()

    new_message = '----- Command History -----'
    cur.execute('SELECT usr_bm_address,date_time,command,message_snippet FROM command_history WHERE ident_bm_address=?' ,[ident_address,])
    while True:
        temp = cur.fetchone()
        if temp == None or temp == '':
            new_message += ln_brk() + '----- End -----'
            break
        else:
            usr_bm_address,date_time,command,message_snippet = temp
            new_message += ln_brk() + 'BM-%s | %s | Command:%s | Message Snippet:%s' % (str(usr_bm_address),str(date_time),str(command),str(message_snippet))
            
    return new_message
    
def perform_command(con,ident_address,usr_bm_address,message,subject):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)
    
    try:
        cur = con.cursor()
        command = (subject.lower()).strip()

        message = str(message)
        subject = str(subject)

        if is_global_admin(con,usr_bm_address):
            usr_access_level = 4
        elif is_adminPlus(con,ident_address,usr_bm_address):
            usr_access_level = 3
        elif is_admin(con,ident_address,usr_bm_address):
            usr_access_level = 2
        elif is_moderator(con,ident_address,usr_bm_address):
            usr_access_level = 1
        else:
            # Everyone has level 0 access
            usr_access_level = 0

        # Log command
        date_time = strftime("%Y-%m-%d:%H",gmtime())
        message_snippet = message.strip()
        message_snippet = message_snippet[:64] #only take the first X number of characters
        cur.execute('INSERT INTO command_history VALUES(?,?,?,?,?,?)', [None,ident_address,usr_bm_address,date_time,command,message_snippet])
        con.commit()
            
        new_subject = '[BM-MODERATOR] ' + str(subject)[:16]
        new_message = ''

        cmd_failed = False
        
        if (command == '--setnick' or command == '--setnickname') and usr_access_level >= 0: #Anyone can do this
            new_message = setNick(con,ident_address,usr_bm_address,message)

        elif command == '--help' and usr_access_level > 0:
            if is_global_admin(con,usr_bm_address):
                new_message = 'Your Access Level is: Owner'
                new_message += ln_brk()
            elif is_adminPlus(con,ident_address,usr_bm_address):
                new_message = 'Your Access Level is: Admin+'
            elif is_admin(con,ident_address,usr_bm_address):
                new_message = 'Your Access Level is: Admin'
            elif is_moderator(con,ident_address,usr_bm_address):
                new_message = 'Your Access Level is: Moderator'
            else:
                new_message = 'Your Access Level is: User'
            
            new_message += ln_brk() + help_file()
            
        elif command == '--clearnick' and usr_access_level > 0:
            new_message = clearNick(con,ident_address,message)            

        elif command == '--addwhitelist' and usr_access_level > 0:
            new_message = addWhiteList(con,ident_address,message,new_subject)

        elif command == '--remwhitelist' and usr_access_level > 0:
            new_message = remWhiteList(con,ident_address,message)

        elif command == '--addblacklist' and usr_access_level > 0:
            new_message = addBlackList(con,ident_address,message)

        elif command == '--remblacklist' and usr_access_level > 0:
            new_message = remBlackList(con,ident_address,message)

        elif command == '--inviteuser' and usr_access_level > 0:
            new_message = inviteUser(con,ident_address,message,new_subject)

        elif command == '--addfilter' and usr_access_level > 0:
            cur.execute('INSERT INTO filter VALUES(?,?)', [None,str(message)])
            new_message = 'Message added to filter list. Any message, to any address on this server, with this text in it will be deleted and no other actions taken.'

        elif command == '--listfilters' and usr_access_level > 0:
            new_message = listFilters(con)

        elif command == '--clearfilter' and usr_access_level > 0:
            tmp_msg = str(message).lower()
            tmp_msg = tmp_msg.strip()
            
            if is_int(tmp_msg):
                try:
                    cur.execute("DELETE FROM filter WHERE id=?",[tmp_msg])
                except:
                    new_message = 'Removing filter (%s) failed. Are you sure you chose the correct filter number?'
                else:
                    new_message = 'Filter (%s) successfully removed.'
            elif tmp_msg == 'all':
                cur.execute("DROP TABLE IF EXISTS filter")
                cur.execute("CREATE TABLE filter(id INTEGER PRIMARY KEY, banned_text TEXT)")
            else:
                new_message = 'Invalid filter ID: %s' % tmp_msg
            
        elif command == '--setlabel' and usr_access_level > 1:
            tmp_label = str(message)
            cur.execute("UPDATE bm_addresses_config SET label=? WHERE bm_address=?",[tmp_label,ident_address])
            new_message = 'Address Label successfully set to [%s].' % tmp_label
            
        elif command == '--setmotd' and usr_access_level > 1:
            tmp_motd = str(message)
            cur.execute("UPDATE bm_addresses_config SET motd=? WHERE bm_address=?",[tmp_motd,ident_address])
            new_message = 'Message Of The Day successfully set to (%s).' % tmp_motd
            
        elif command == '--addmoderator' and usr_access_level > 1:
            new_message = addModerator(con,ident_address,message,new_subject)
            
        elif command == '--remmoderator' and usr_access_level > 1:   
            new_message = remPrivilege(con,ident_address,message)
        
        elif command == '--listmoderators' and usr_access_level > 1:
            new_message = listModerators(con,ident_address)
            
        elif command == '--addadmin' and usr_access_level > 2:
            new_message = addAdmin(con,ident_address,message,new_subject)
            
        elif command == '--remadmin' and usr_access_level > 2:  
            new_message = remPrivilege(con,ident_address,message)

        elif command == '--listadmins' and usr_access_level > 2:
            new_message = listAdmins(con,ident_address)

        elif command == '--addadmin+' and usr_access_level > 3:
            new_message = addAdminPlus(con,ident_address,message,new_subject)
            
        elif command == '--remadmin+' and usr_access_level > 3:
            new_message = remPrivilege(con,ident_address,message)

        elif command == '--listadmin+' and usr_access_level > 3:
            new_message = listAdminPlus(con,ident_address)

        elif command == '--sendbroadcast' and usr_access_level > 1:
            send_broadcast(con,ident_address,new_subject,message)
            
        elif command == '--listusers' and usr_access_level > 1:
            new_message = listUsers(con,ident_address)
            
        elif command == '--setmailinglist' and usr_access_level > 2:
            cur.execute("UPDATE bm_addresses_config SET echo_address=? WHERE bm_address=?",['false',ident_address])
            new_message = 'Address set as a Mailing List. It will now broadcast messages that are sent to it.'

        elif command == '--setecho' and usr_access_level > 2:
            cur.execute("UPDATE bm_addresses_config SET echo_address=? WHERE bm_address=?",['true',ident_address])
            new_message = 'Address set as an Echo Address. It will now reply to all messages sent to it.'

        elif command == '--setblacklist' and usr_access_level > 2:
            cur.execute("UPDATE bm_addresses_config SET whitelisted=? WHERE bm_address=?",['false',ident_address])
            new_message = 'Address Blacklisted. Anyone that has not been Blacklisted can use this address.'

        elif command == '--setwhitelist' and usr_access_level > 2:
            cur.execute("UPDATE bm_addresses_config SET whitelisted=? WHERE bm_address=?",['true',ident_address])
            new_message = 'Address Whitelisted. Only Whitelisted users will be able to use this address. Use "--inviteUser" to invite new users.'

        elif command == '--setmaxlength' and usr_access_level > 1:
            message = message.lower()
            message = message.strip()
            if is_int(message):
                cur.execute("UPDATE bm_addresses_config SET max_msg_length=? WHERE bm_address=?",[int(message),ident_address])
                new_message = 'Maximum message length successfully changed to %s characters. Messages longer than this will be truncated.' % message
            else:
                cmd_failed = True

        elif command == '--enable' and usr_access_level > 1:
            cur.execute("UPDATE bm_addresses_config SET enabled=? WHERE bm_address=?",['true',ident_address])
            new_message = 'Address enabled.'

        elif command == '--disable' and usr_access_level > 1:
            cur.execute("UPDATE bm_addresses_config SET enabled=? WHERE bm_address=?",['false',ident_address])
            new_message = 'Address disabled. NOTE: Admins and Moderators will still be able to perform commands.'

        elif command == '--generatenewaddress' and usr_access_level > 2:
            if message != '':
                if len(message) <= 32:
                    tmp_label = str(message)
                    new_address = generateAddress(con,tmp_label)
                    new_address = new_address[3:]
                    new_message = 'Address (BM-%s) successfully generated with Label (%s)' % (new_address,tmp_label)
                else:
                    new_address =  generateAddress(con)
                    new_address = new_address[3:]
                    tmp_label = 'no label'
                    new_message = 'Label too long (Max 32). Address (BM-%s) successfully generated with default Label (%s)' % (new_address,tmp_label)
            else:
                new_address =  generateAddress(con)
                new_address = new_address[3:]
                tmp_label = 'no label'
                new_message = 'No Label specified. Address (BM-%s) successfully generated with default Label (%s)' % (new_address,tmp_label)

            # Initalize address in database
            throwAway = get_bm_ident_info(con,ident_address)
            
            cur.execute("UPDATE bm_addresses_config SET label=? WHERE bm_address=?",[tmp_label,ident_address])
            con.commit()
            
            throwAway = addAdmin(con,new_address,usr_bm_address,new_subject)
            
        elif command == '--getstats' and usr_access_level > 1:
            new_message = getStats(con,ident_address,message)
            
        elif command == '--getcommandhistory' and usr_access_level > 1:
            new_message = getCommandHistory(con,ident_address)
        
        elif command == '--getinfo' and usr_access_level > 2:
            new_message = getInfo(con)
            
        elif usr_access_level > 0:
            new_message = 'Unknown command: %s' % str(subject)
            # Note: user with access level 0 will not get a reply. This prevents a DOS attack vector.
        con.commit()
        
        if cmd_failed:
            new_message = 'Command failed. (%s) (%s)' %(subject,message)
            
        if new_message != '':
            send_message(con,usr_bm_address,ident_address,new_subject,new_message)
            
    except Exception as e:
        print 'perform_command ERROR: ',e

def echo(con,myAddress,replyAddress,message,subject):
    try:
        apiurl = api_data(con)
        if not apiurl: return
        api = xmlrpclib.ServerProxy(apiurl)

        temp = get_bm_ident_info(con, myAddress)
        if temp == None:
            print 'echo error, no data'
            return None

        label,enabled,motd,whitelisted,max_msg_length,echo_address = temp

        subject = subject.lstrip() # Removes prefix white spaces

        if (len(subject) > 32): # Truncates the subject if it is too long
            subject = (subject[:32] + '... Truncated')

        #if (str(subject[:len(label)+1]) != '%s:' % label):
        #    subject = '%s: %s'% (label,subject) #only adds prefix if not already there
        
        if (len(message) > int(max_msg_length)) and (str(max_msg_length) != '0'): # Truncates the message if it is too long
            message = (message[:int(max_msg_length)] + '... Truncated to %s characters.\n' % max_msg_length)
        
        echoMessage = ('Message successfully received at ' + strftime("%Y-%m-%d %H:%M:%S",gmtime()) + ' UTC/GMT.\n' + '-------------------------------------------------------------------------------\n' + message + '\n\n\n' + str(motd))

        send_message(con,replyAddress,myAddress,subject,echoMessage)
    except Exception as e:
        print 'echo ERROR: ',e

def mailing_list(con,myAddress,replyAddress,message,subject):
    try:
        cur = con.cursor()

        temp = get_bm_ident_info(con, myAddress) # Get info about the address it was sent to(our address)
        if temp == None:
            print 'mailing_list error, no data'
            return None

        label,enabled,motd,whitelisted,max_msg_length,echo_address = temp
        # Only label,motd,and max_msg_length used here
        max_msg_length = int(max_msg_length)

        subject = subject.lstrip() # Removes left spaces

        if (len(subject) > 64): # Truncates the subject if it is too long
            subject = (subject[:64] + '...')
            
        if (str((subject[:3]).lower()) == 're:'):
                subject = subject[3:] # Removes re: or RE: from subject
                
        subject = subject.lstrip() # Removes left spaces
                
        if (str(subject[:len(label)+2]) == '[%s]'% label):
            subject = subject[len(label)+2:] # Removes label

        subject = subject.lstrip() # Removes left spaces
            
        subject = '[%s] %s'% (label,subject)
        
        if (len(message) > max_msg_length) and (str(max_msg_length) != '0'): # Truncates the message if it is too long
            message = (message[:max_msg_length] + '... Truncated to %s characters.\n' % max_msg_length)


        # Get nickname
        cur.execute("SELECT ident_bm_address,nickname FROM users_config WHERE usr_bm_address=?",[replyAddress])
        while True:
            temp = cur.fetchone()
            if temp == None or temp == '':
                nickname = 'anonymous'
                break
            else:
                ident_address,nickname = temp

                if ident_address == myAddress:
                    if nickname == None or nickname == '':                        
                        nickname = 'anonymous'
                    else:
                        nickname = str(nickname)
                        
                    break     

        message = strftime("%a, %Y-%m-%d %H:%M:%S UTC",gmtime()) + '   Message ostensibly from BM-%s (%s):\n%s\n\n%s' % (replyAddress,nickname,motd,message) 

        send_broadcast(con,myAddress,subject,message) # Build the message and send it
    except Exception as e:
        print 'mailing_list ERROR: ',e

def send_message(con,to_address,from_address,subject,message):
    try:
        apiurl = api_data(con)
        if not apiurl: return
        api = xmlrpclib.ServerProxy(apiurl) # Connect to BitMessage
        subject = subject.encode('base64') # Encode the subject
        message = message.encode('base64') # Encode the message.
        api.sendMessage(to_address,from_address,subject,message) # Build the message and send it

        # Add to daily stats
        date_day = strftime("%Y-%m-%d",gmtime())
        cur = con.cursor()
        cur.execute('SELECT id,bm_address,num_sent_messages FROM stats WHERE date_day=?' ,[date_day,])
        temp = cur.fetchone()
        if temp == None or temp == '':
            # Inserting new day
            cur.execute('INSERT INTO stats VALUES(?,?,?,?,?)', [None,date_day,from_address,0,1])
        else:
            id_num,bm_address,num_sent_messages = temp
            if bm_address == from_address:
                num_sent_messages += 1
                cur.execute("UPDATE stats SET num_sent_messages=? WHERE id=?", (num_sent_messages,id_num))
        con.commit()

        print 'Message sent'
    except Exception as e:
        print 'send_message ERROR: ',e

def send_broadcast(con,broadcast_address,subject,message):
    try:
        apiurl = api_data(con)
        if not apiurl: return
        api = xmlrpclib.ServerProxy(apiurl) # Connect to BitMessage
        subject = subject.encode('base64') # Encode the subject
        message = message.encode('base64') # Encode the message.
        api.sendBroadcast(broadcast_address,subject,message) # Build the broadcast and send it

        # Add to daily stats
        date_day = strftime("%Y-%m-%d",gmtime())
        cur = con.cursor()
        cur.execute('SELECT id,bm_address,num_sent_broadcasts FROM stats WHERE date_day=?' ,[date_day,])
        temp = cur.fetchone()
        if temp == None or temp == '':
            # Inserting new day
            cur.execute('INSERT INTO stats VALUES(?,?,?,?,?)', [None,date_day,broadcast_address,1,0])
        else:
            id_num,bm_address,num_sent_broadcasts = temp
            if bm_address == broadcast_address:
                num_sent_broadcasts += 1
                cur.execute("UPDATE stats SET num_sent_broadcasts=? WHERE id=?", (num_sent_broadcasts,id_num))
        con.commit()


        print 'Broadcast sent'
    except Exception as e:
        print 'send_broadcast ERROR: ',e

def accept_invite(con,ident_address,usr_bm_address,subject):
    usr_bm_address = format_address(usr_bm_address)
    ident_address = format_address(ident_address)

    subject = str(subject).lower()
    subject = subject.lstrip()
    
    if 'accept' in subject:
        cur = con.cursor()
        if is_address(usr_bm_address):
            cur.execute("SELECT id,ident_bm_address,whitelisted_blacklisted FROM users_config WHERE usr_bm_address=?",[usr_bm_address])
            while True:
                temp = cur.fetchone()

                if temp == None or temp == '':
                    return False
                else:
                    id_num,ident_bm_address,whitelisted_blacklisted = temp

                    if ident_bm_address == ident_address and whitelisted_blacklisted == 'invited':
                        addWhiteList(con,ident_address,usr_bm_address,'[BM-Moderator]')
                        return True
    else:
        return False

def main_loop():
    print 'bmModerator - Starting up main loop in 10 seconds.'
    time.sleep(10) # Sleep to allow bitmessage to start up
    con = lite.connect(database) #Only connects to database when needed
    while True:
        try:
            # Check if messages in inbox
            if check_if_new_msg(con):
                print 'Message found. Processing'
                temp = process_new_message(con)
                if temp == None:
                    print 'No actions'
                    pass # Perform no actions
                else:
                    toAddress,fromAddress,message,subject = temp
                    
                    if is_blacklisted(con,toAddress,fromAddress): # Check if address is blacklisted
                        print 'Blacklisted User'
                        pass # Perform no actions
                    elif is_command(subject): # Check if a command is being attempted
                        print 'Command discovered: ',str(subject)
                        throwAway = get_bm_ident_info(con,toAddress)
                        # Initalize address if not already done. throwAway variable is not used                                                      
                        perform_command(con,toAddress,fromAddress,message,subject) # Performs command actions and sends necessary broadcast/message
                    else:
                        print 'Other discovered'
                        temp2 = get_bm_ident_info(con,toAddress) # Get info about the address it was sent to(our address)
                        if temp2 != None:
                            label,enabled,motd,whitelisted,max_msg_length,echo_address = temp2
                            
                            if accept_invite(con,toAddress,fromAddress,subject):
                                print 'Accepting invite'
                                tmp_msg = 'Congratulations, you have been added to this address. You can set your nickname by replying with Subject:"--setNick" and Message:"Your Nickname"' % (usr_bm_address,ident_address)
                                send_message(con,fromAddress,toAddress,'[BM-MODERATOR]',tmp_msg)
                            elif (str(enabled).lower() != 'false'): 
                                # Determine permissions of ident address and user address
                                if (str(whitelisted).lower() != 'true'):
                                    performAction = True
                                elif (str(whitelisted).lower() == 'true' and is_whitelisted(con,toAddress,fromAddress)):
                                    performAction = True
                                elif is_global_admin(con,fromAddress):
                                    performAction = True
                                elif is_adminPlus(con,toAddress,fromAddress):
                                    performAction = True
                                elif is_admin(con,toAddress,fromAddress):
                                    performAction = True
                                elif is_moderator(con,toAddress,fromAddress):
                                    performAction = True
                                else:
                                    performAction = False
                                    
                                if performAction:
                                    if str(echo_address).lower() == 'true':
                                        print 'Echo'
                                        echo(con,toAddress,fromAddress,message,subject)
                                    else:
                                        print 'Mailing List'
                                        mailing_list(con,toAddress,fromAddress,message,subject)
                                else:
                                    print 'Insufficient Privileges'
                print 'Finished with Message.'

            # Check again, this time to determine sleep time and whether or not to close the database connection
            if check_if_new_msg(con): 
                print 'sleep 1'
                time.sleep(1) # How often to loop when there are messages
            else:
                time.sleep(15) # How often to run the loop on no msg

        except Exception as e:
            print 'main_loop ERROR: ',e
            print 'sleep 30'
            time.sleep(30)
    con.close()

def initConfig():
    print '-Initalizing Moderator-\n'

    print 'Would you like to (I)nitalize the application, update the (A)PI info,'
    print '(S)et the global administrator, or (G)enerate a new random identity?(I/A/S/G)'
    uInput = raw_input('> ')
    if uInput.lower() == 'i':
        print 'Any existing databases will be deleted.'
        print 'Are you sure that you want to continue? (Y/N)'
        uInput = raw_input('> ')
        if uInput.lower() == 'y':
            create_db()
            print 'Databases Created'
        else:
            print '-Aborted-\n'
            return ''
    
    elif uInput.lower() == 'a':
        con = lite.connect(database) 
        cur = con.cursor()
        
        print "Please enter the following API Information\n"
        api_port = raw_input('API Port> ')
        api_address = raw_input('API Address> ')
        api_username = raw_input('API username> ')
        api_password = raw_input('API Password> ')

        api_port = str(api_port)
        api_address = str(api_address)
        api_username = str(api_username)
        api_password  = str(api_password)
        
        cur.execute("UPDATE api_config SET api_port=? WHERE id=?",(api_port,0))
        cur.execute("UPDATE api_config SET api_address=? WHERE id=?",(api_address,0))
        cur.execute("UPDATE api_config SET api_username=? WHERE id=?",(api_username,0))
        cur.execute("UPDATE api_config SET api_password=? WHERE id=?",(api_password,0))
        print '\nSuccessfully updated API information.'
        print 'Please setup the apinotifypath through Bitmessage if you have not already.'
        print 'Please setup a Global Administrator if you have not already.\n'

        con.commit()
        cur.close()
        con.close()
        
    elif uInput.lower() == 's':
        while True:
            print "Please enter the Gloabl Administrator's Bitmessage Address"
            uInput = raw_input('> ')

            if is_address(uInput):
                bm_address = uInput
                
                if bm_address[:3].lower() == 'bm-':
                    bm_address = bm_address[3:]
                    
                con = lite.connect(database) 
                cur = con.cursor()
                cur.execute("UPDATE api_config SET global_admin_bm_address=? WHERE id=?",(bm_address,0))
                print 'Global Admin successfully changed. This address can perform "Owner" commands.'
                con.commit()
                cur.close()
                con.close()
                break
            else:
                print 'Invalid address. Try again'
    
    elif uInput.lower() == 'g':
        con = lite.connect(database)  
        cur = con.cursor()
        the_address = generateAddress(con)
        if decodeAddress(the_address):
            # Let's alert the global admin. Find address if it exists
            cur.execute("SELECT global_admin_bm_address FROM api_config WHERE id=?",('0',))
            temp = cur.fetchone()

            if temp == None or temp == '':
                print '\nAddress Generated (BM-%s)\n' % the_address
                print 'Global Admin not set. Auto-Notification not sent.'
                pass
            else:
                global_admin_bm_address = str(temp[0])
                addAdmin(con,the_address,global_admin_bm_address,'[BM-Moderator]')
            print '\nAddress Generated (BM-%s) and Global Admin (BM-%s) notified.' % (the_address,global_admin_bm_address)
        else:
            print 'ERROR generating address: ', the_address

        cur.close()
        
    print 'Finished\n'
            
def main():
    try:
        arg = sys.argv[1]
            
        if arg == "startingUp":
            main_loop()
            sys.exit()
                                                  
        elif arg == "newMessage":
            # TODO, check if process already running, if not, start
            # - This could be used in the event of this process stopping for an unknown reason
            sys.exit()
            
        elif arg == "newBroadcast":
            sys.exit()
                                                  
        elif arg == "initalize":
            initConfig()
            sys.exit()
            
        elif arg == "apiTest":
            pass
            # TODO, add apiTest function
        else:
            print 'unknown command  (%s)' % arg
            sys.exit() # Not a relevant argument, exit
    except Exception as e:
        print e

if __name__ == '__main__':
    try:
        main()
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print ("Crtl+C Pressed. Shutting down.")
