'''
Created on Aug 6, 2015

@author: waseem
'''

#!/usr/bin/env

import MySQLdb
import GeoIP
import datetime
import sqlite3

KIPPO_PUBLIC_DATABASE = "kippo"
KIPPO_MERGED = 'logsql_merged.sqlite'
#date = raw_input("Please Enter the month # ")
date= '09' 
DATA_SESSION = "SELECT id,ip,client FROM sessions WHERE starttime LIKE '2015-"+date+"%'" 
SESSION_STRUCTURE = '''CREATE TABLE IF NOT EXISTS sessions(
        id TEXT,
        ip varchar(15),
        ip_country text,
        client text);'''
POPULATE_SESSION = '''INSERT INTO sessions VALUES (?,?,?,?)'''  

DATA_AUTH = "SELECT * FROM auth WHERE TIMESTAMP LIKE  '2015-09%'"
AUTH_STRUCTURE = '''CREATE TABLE IF NOT EXISTS auth(
        id TEXT,
        session Text,
        success int(1),
        username,            
        password,
        timestamp text);'''
POPULATE_AUTH = '''INSERT INTO auth VALUES (?,?,?,?,?,?)'''

DATA_INPUT = "SELECT * FROM input WHERE timestamp LIKE '%2015-"+date+"%'"
INPUT_STRUCTURE = '''CREATE TABLE IF NOT EXISTS input(
        id int(11),
        session char(32),
        timestamp text,
        realm varchar(50),
        success tinyint(1),            
        input text);'''
POPULATE_INPUT = '''INSERT INTO input VALUES (?,?,?,?,?,?)'''

DATA_CLIENT = "SELECT * FROM clients"
CLIENT_STRUCTURE = '''CREATE TABLE IF NOT EXISTS clients(
        id int(4) PRIMARY KEY,
        version  varchar(50));'''
POPULATE_CLIENT = '''INSERT INTO clients VALUES (?,?)''' 

DATA_TOPUSER = "SELECT count(username),username FROM auth GROUP BY username ORDER BY count(username) DESC"
TOPUSER_STRUCTURE = '''CREATE TABLE IF NOT EXISTS topusers(
        hits int(11),
        username varchar(100));'''
POPULATE_TOPUSER = '''INSERT INTO topusers VALUES (?,?)'''

DATA_TOPPASSWORD = "SELECT count(password),password FROM auth GROUP BY password ORDER BY count(password) DESC"
TOPPASSWORD_STRUCTURE = '''CREATE TABLE IF NOT EXISTS toppasswords(
        hits int(11),
        passwords varchar(100));'''
POPULATE_TOPPASSWORD = '''INSERT INTO toppasswords VALUES (?,?)'''

DATA_TOPCLIENT = "SELECT count(sessions.client),clients.version FROM sessions INNER JOIN clients ON (sessions.client = clients.id)  Group by sessions.client ORDER BY count(sessions.client) DESC"
TOPCLIENT_STRUCTURE = '''CREATE TABLE IF NOT EXISTS topclients(
        hits int(11),
        client varchar(100));'''
POPULATE_TOPCLIENT = '''INSERT INTO topclients VALUES (?,?)'''

DATA_TOPATTACKER = "SELECT count(ip),ip,ip_country FROM sessions Group by ip ORDER BY count(ip) DESC"
TOPATTACKER_STRUCTURE = '''CREATE TABLE IF NOT EXISTS topips(
        hits int(11),
        ip varchar(100),
        ip_country varchar(100));'''
POPULATE_TOPATTACKER = '''INSERT INTO topips VALUES (?,?,?)'''


#Generate the Country name base on the IP address
def getCountry(ipaddress):
        i=ipaddress.split('.')
        if ((i[0] == '10') or (i[0] == '172' and (i[1]>15 or i[1]<32)) or (i[0] == '192' and i[1] == '168')  ):
            return "private"
        elif ipaddress == '103.54.248.249':
            return 'Vietnam'
        elif ipaddress == '103.55.88.13':
            return 'India'
        elif ipaddress == '138.118.125.2':
            return 'Panama'
        elif ipaddress == '103.55.36.43':
            return 'Indonesia'
        elif ipaddress == '185.108.196.178':
            return 'Russia'
        elif ipaddress == '103.55.36.67':
            return 'Indonesia'
        elif ipaddress == '103.55.36.43':
            return 'Indonesia'
        elif ipaddress == '45.79.200.131':
            return 'United States'
        elif ipaddress == '138.121.58.165':
            return 'Brazil'
        elif ipaddress == '45.79.9.231':
            return 'United States'
        elif ipaddress == '103.54.200.227':
            return 'India'
        elif ipaddress == '138.185.177.230':
            return 'Brazil'
        elif ipaddress == '138.186.95.238':
            return 'Brazil'
        elif ipaddress == '138.121.182.226':
            return 'Brazil'
        elif ipaddress == '45.115.16.101':
            return 'India'
        elif ipaddress == '185.103.245.183':
            return 'Iran'
        elif ipaddress == '103.55.104.140':
            return 'India'
        elif ipaddress == '138.204.73.192':
            return 'Brazil'
        elif ipaddress == '185.103.244.210':
            return 'Iran'
        elif ipaddress == '138.121.58.31':
            return 'Brazil'
        elif ipaddress == '45.79.204.224':
            return 'United States'
        
        
        
        
        
        
        else: 
            gi = GeoIP.open("GeoLiteCityt.dat",GeoIP.GEOIP_STANDARD);
            if "::ffff:" in ipaddress:
                ipaddress = ipaddress.split("::ffff:")
                ipaddress = ipaddress[1]
            gir = gi.record_by_name(ipaddress)
            if gir is None:
                print("In 2nd DB")
                gi = GeoIP.open("GeoLiteCity.dat",GeoIP.GEOIP_STANDARD);
                gir = gi.record_by_name(ipaddress)
            if gir is not None:
                return gir['country_name']
            else:
                print(ipaddress, " not in Geolite DB")

#Get the Connection
def getMySqlConnection(database):
    'This function returns the connection'
    #createDatabase(database);
    print ("in getMySqlConnection")
    return MySQLdb.connect(host="115.186.132.21",user="root",passwd="honeydrive",db=database,port=3307)

#Create the Database
def createDatabase(database):
    'This function create the database if not exist'
    sql = "CREATE DATABASE IF NOT EXISTS "+database
    db = MySQLdb.connect("localhost","root","honeydrive",database)
    try:
        db.cursor().execute(sql)
    except Exception:
        print (Exception.message) 
        return 1
    else:
        return 0

#Provide the Cursor of the Database
def getMySqlCursor(database):
    'This function create Connections with the Database'
    db = MySQLdb.connect(host="115.186.132.21",user="root",passwd="honeydrive",db=database,port=3307)
    return db.cursor()

#@UndefinedVariable
def getSqliteConnection(database):
    'This function returns the connection'
    return sqlite3.connect(database)


#Provide the Cursor of the Database
def getSqliteCursor(database):
    'This function create Connections with the Database'
    return sqlite3.connect(database).cursor()

# Connect to the Dionaea database to Insert specific records
def createTable(database, structure):
    'This function create the new table on the bases of Structure'
    getSqliteCursor(database).execute(structure)
    print ("Table created Successfully")

#Connect to the logsql database and get the specific data
def getSqliteRecord(query, database):
    "This function will create a connection and store results"    
    cursor = getSqliteCursor(database)
    return cursor.execute(query)
                          
#Connect to the logsql database and get the specific data
def getMySqlRecord(query):
    "This function will create a connection and store results"
    print ("in getdata")
    db = MySQLdb.connect(host="115.186.132.21",user="root",passwd="honeydrive",db="kippo",port=3307)
    cursor = db.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    #for i in result: 
    #    print (i)
    return result


#Add new Data columns to the table
def alterTable(database,table,column,datatype):
    'This function will create the percentage of the stuff you required'
    getMySqlCursor(database).execute("ALTER TABLE "+table+" ADD COLUMN "+column+" "+datatype)
    print ("Column ",column, " has been created in ", table, " with datatype ",datatype)

#Drop the Specific table
def dropTable(database,table):
    'This function provide a facility to drop any table'
    getSqliteCursor(database).execute("DROP TABLE " + table)
    print ("Table",table,"Deleted Successfully")

def getTableCount (table_name, connection):
    'This will return the no of tables'
    return connection.cursor().execute("SHOW COLUMNS FROM " +table_name)

def populateTable(data, connection, query):
    'This function will populate the tables' 
    if "(?,?,?,?)" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1],getCountry(i[1]), i[2]))
            except sqlite3.IntegrityError:
                print IntegrityError.message
                break;
    elif "(?,?,?,?,?,?)" in query:
        for i in data:
            try:
                try:
                    user = unicode(str(i[3]))
                except Exception:
                    user = i[3].decode('latin-1')
                    
                try:                  
                    password = unicode(str(i[4]))
                except Exception:
                    password = i[4].decode('latin-1')
                    
                 
                connection.cursor().execute(query,(i[0], i[1], i[2],user,password, i[5]))
            except Exception :
                print (i)
    elif "(?,?,?)" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1], i[2]))
            except sqlite3.IntegrityError:
                print (IntegrityError.message)
                break;
    elif "(?,?)" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1]))
            except sqlite3.IntegrityError:
                print (i[0],i[1])
                break;
    connection.commit()
    print "Total rows updated", connection.total_changes
    print "Completed Loop"
    
#createTable(KIPPO_MERGED, SESSION_STRUCTURE)
#populateTable(getMySqlRecord(DATA_SESSION), getSqliteConnection(KIPPO_MERGED), POPULATE_SESSION)

#createTable(KIPPO_MERGED, AUTH_STRUCTURE)
#populateTable(getMySqlRecord(DATA_AUTH), getSqliteConnection(KIPPO_MERGED), POPULATE_AUTH)

#createTable(KIPPO_MERGED, CLIENT_STRUCTURE)
#populateTable(getMySqlRecord(DATA_CLIENT), getSqliteConnection(KIPPO_MERGED), POPULATE_CLIENT)

#createTable(KIPPO_MERGED, INPUT_STRUCTURE)
#populateTable(getMySqlRecord(DATA_INPUT), getSqliteConnection(KIPPO_MERGED), POPULATE_INPUT)

createTable(KIPPO_MERGED, TOPUSER_STRUCTURE)
populateTable(getSqliteRecord(DATA_TOPUSER,KIPPO_MERGED), getSqliteConnection(KIPPO_MERGED), POPULATE_TOPUSER)

createTable(KIPPO_MERGED, TOPPASSWORD_STRUCTURE)
populateTable(getSqliteRecord(DATA_TOPPASSWORD,KIPPO_MERGED), getSqliteConnection(KIPPO_MERGED), POPULATE_TOPPASSWORD)

#dropTable(KIPPO_MERGED, 'top_protocols')

createTable(KIPPO_MERGED, TOPCLIENT_STRUCTURE)
populateTable(getSqliteRecord(DATA_TOPCLIENT,KIPPO_MERGED), getSqliteConnection(KIPPO_MERGED), POPULATE_TOPCLIENT)

createTable(KIPPO_MERGED, TOPATTACKER_STRUCTURE)
populateTable(getSqliteRecord(DATA_TOPATTACKER,KIPPO_MERGED), getSqliteConnection(KIPPO_MERGED), POPULATE_TOPATTACKER)
