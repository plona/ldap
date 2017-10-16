#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Opcje:
[-c | --config ]    ścieżka do pliku konfiguracyjnego. Domyślnie $HOME/.ldappyrc
[-h | --help]
"""

import sys
import os
import getopt
import ConfigParser
import locale
import subprocess
import time
import ldap
import pprint
import json

from dialog import Dialog

class config:
    def __init__(self, rcfile):
        self.config = ConfigParser.ConfigParser()
        self.config.read(rcfile)
        self.rootDN = self.config.get("root", "rootDN")
        try:
            self.rootPW = self.config.get("root", "rootPW")
        except ConfigParser.NoOptionError:
            self.rootPW = None
        self.ldapHost = self.config.get("ldap", "ldapHost")
        self.ldapBase = self.config.get("ldap", "ldapBase")
        self.ldapUBase = self.config.get("ldap", "ldapUBase") + "," + self.ldapBase
        # user data
        self.ldapUserCn = None
        self.ldapUserGivenName = None
        self.ldapUserSn = None
        self.ldapUserPassword = None
        self.ldapUserUidNumber = None
        self.ldapUserGidNumber = None
        self.ldapUserGroups = list()
        # filter param
        self.userAttr = self.config.get("filter", "userAttr")
        self.userFilter = self.config.get("filter", "userFilter")
        self.groupOfNames = self.config.get("filter", "groupOfNames")
        self.groupId = self.config.get("filter", "groupId")
        self.userId  = self.config.get("filter", "userId")


class myldap:
    def __init__(self, c, d):
        self.c = c
        self.d = d
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 1)
        ldap.set_option(ldap.OPT_TIMEOUT, 2)
        ldap.set_option(ldap.OPT_TIMELIMIT, 2)
        self.userList = list()
        self.groupList = list()
        try:
            self.myl = ldap.initialize(self.c.ldapHost)
            self.myl.protocol_version = ldap.VERSION3
        except ldap.LDAPError, e:
            print e
            raise
        try:
            result = self.myl.simple_bind(self.c.rootDN, self.c.rootPW)
            who= self.myl.whoami_s()
            if who != "dn:" + self.c.rootDN:
                self.d.msg(u"Błędne poświadczenia\n(dn lub hasło)")
                self.d.clear_screen()
                sys.exit(1)
        except ldap.LDAPError, e:
            print e
            raise

    def search(self, basedn, searchFilter, searchAttr):
        searchScope = ldap.SCOPE_SUBTREE
        # print "==========="
        # print basedn
        # print searchFilter
        # print searchAttr
        # print "==========="
        try:
            ldap_result_id = self.myl.search(basedn, searchScope, searchFilter, searchAttr)
            result_set = list()
            while True:
                result_type, result_data = self.myl.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            return (result_set)
        except ldap.LDAPError, e:
            print e
            raise

    def checkUser(self, uname):
        f = "(&(" + self.c.userAttr + "=" + uname + ")" + self.c.userFilter + ")"
        r = self.search(self.c.ldapUBase, f, [self.c.userAttr])
        return (len(r))

    def getMaxUidNumber(self):
        f = self.c.userId
        a = "uidNumber"
        r = self.search(self.c.ldapUBase, f, [a])
        ul = list()
        for rEl in r:
            for aEl in rEl:
                if aEl[len(aEl)-1].has_key(a):
                    ul.append( int(aEl[len(aEl)-1][a][0]) )
        if len(ul) > 0:
            return max(ul)
        else:
            return 0

    def getMaxGidNumber(self):
        f = self.c.groupId
        a = "gidNumber"
        r = self.search(self.c.ldapBase, f, [a])
        gl = list()
        for rEl in r:
            for aEl in rEl:
                if aEl[len(aEl)-1].has_key(a):
                    gl.append( int(aEl[len(aEl)-1][a][0]) )
        if len(gl) > 0:
            return max(gl)
        else:
            return 0

    def getGroups(self):
        f = self.c.groupOfNames
        a = "cn"
        r = self.search(self.c.ldapBase, f, [a])
        gl = list()
        for rEl in r:
            for aEl in rEl:
                if aEl[len(aEl)-1].has_key(a):
                    gl.append(aEl[len(aEl)-1][a][0])
        return  gl

    def addUser(self):
        self.d.msg(u"Jeszcze nie gotowe")
        dn = "cn=" + self.c.ldapUserCn + "," + self.c.ldapUBase
        cmds = json.loads(self.c.config.get("ldap", "ldapClass"))
        print dn
        print cmds
        time.sleep(5)


class mydialog:
    def __init__(self, c):
        self.c = c
        self.myd = Dialog(dialog="dialog")

    def myGetPass(self):
        self.myd.set_background_title(u"U: " + self.c.rootDN + ";" + u" S: " + self.c.ldapHost)
        if self.c.rootPW is None:
            code, password = self.myd.passwordbox(u"Hasło", insecure=True)
            if self.myd.OK == code:
                self.c.rootPW = password
            else:
                sys.exit(2)

    def clear_screen(self):
        # This program comes with ncurses
        program = "clear"

        try:
            p = subprocess.Popen([program], shell=False, stdout=None,
                                 stderr=None, close_fds=True)
            retcode = p.wait()
        except os.error, e:
            self.msg("Unable to execute program '%s': %s." % (program,
                                                              e.strerror),
                     title="Error")
            return False

        if retcode > 0:
            msg = "Program %s returned exit status %d." % (program, retcode)
        elif retcode < 0:
            msg = "Program %s was terminated by signal %d." % (program, -retcode)
        else:
            return True

        self.msg(msg)
        return False

    def msg(self, message="Not yet ready", title=None):
        if title is not None:
            self.myd.set_background_title(title)
        self.myd.msgbox(message)

    def myMenu(self):
        code, tag = self.myd.menu("Wybierz",
                                choices=[
                                    ("1", u"Dodaj nowego użytkownika"),
                                    ("2", u"Usuń istniejącego użytkownika"),
                                    ("3", u"Dodaj użytkownika do grupy"),
                                    ("4", u"Usuń użytkownika z grupy"),
                                    ("5", u"Zmień hasło ldap")
                                ])
        if self.myd.OK == code:
            return(tag)
        else:
            self.clear_screen()
            # sys.exit(2)
            return "-1"

    def getUserData(self, guId="1"):
        elements = [
            (u"cn:", 1, 1, "", 1, 20, 20, 0, 0x0),
            (u"Imię", 2, 1, "", 2, 20, 60, 0, 0x0),
            (u"Nazwisko:", 3, 1, "", 3, 20, 60, 0, 0x0),
            (u"Hasło", 4, 1, "", 4, 20, 20, 0, 0x1)
            ]
        if guId != "0":
            elements.append((u"uidNumber", 5, 1, guId, 5, 20, 4, 0, 0x0))
            elements.append((u"gidNumber", 6, 1, guId, 6, 20, 4, 0, 0x0))
        code, fields = self.myd.mixedform(u"Nowy użytkownik LDAP:", elements, width=77, insecure=True)
        if self.myd.OK == code:
            self.c.ldapUserCn = fields[0]
            self.c.ldapUserGivenName = fields[1]
            self.c.ldapUserSn = fields[2]
            self.c.ldapUserPassword = fields[3]
            if guId != "0":
                self.c.ldapUserUidNumber = fields[4]
                self.c.ldapUserGidNumber = fields[5]
            return True
        else:
            return False

    def getUserGroups(self, groupList=list(), title=""):
        self.c.ldapUserGroups = list()
        items = list()
        for el in groupList:
            items.append((el, el, False))
        print items
        code, l = self.myd.buildlist(text=u"Wybierz", items=items, visit_items=True, title=title)
        if self.myd.OK == code:
            self.c.ldapUserGroups = l
        return

def main(argv):

    def usage():
        print(globals()['__doc__'])
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv, "c:h", ["config=", "help"])
    except getopt.GetoptError:
        usage()

    rcfile = os.getenv("HOME") + "/." + os.path.basename(sys.argv[0]).replace(".", "") + "rc"
    for opt, arg in opts:
        if opt in ("-c", "--config"):
            rcfile = arg
        if opt in ("-h", "--help"):
            usage()

    locale.setlocale(locale.LC_ALL, '')

    c = config(rcfile=rcfile)
    d = mydialog(c)

    d.myGetPass()

    l = myldap(c, d)  # try to bind to ldap server with root credentials (in __init__)

    while True:
        what = d.myMenu()
        if   "1" == what:
            mUid = l.getMaxUidNumber() + 1
            mGid = l.getMaxGidNumber() + 1
            if d.getUserData(guId=str(max(mUid,mGid))):
                if l.checkUser(c.ldapUserCn) > 0:
                    d.msg(u"Użytkownik: " + c.ldapUserCn + u" już istnieje!")
                    continue
            gl = l.getGroups()
            d.getUserGroups(groupList=gl, title=u"Dodaj użytkownika do grup")
            l.addUser()
        elif "2" == what:
            pass
        elif "3" == what:
            pass
        elif "4" == what:
            pass
        elif "5" == what:
            pass
        else:
            break

    pprint.pprint(vars(c))

if __name__ == "__main__":
    main(sys.argv[1:])
