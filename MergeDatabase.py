'''
Created on Aug 4, 2015

@author: waseem
'''
#!/usr/bin/python

import sqlite3
import ast
import pygeoip
from datetime import datetime
import re



PUBLIC19_DATABASE = 'logsql19.sqlite'
PUBLIC21_DATABASE = 'logsql21.sqlite'
PUBLIC62_DATABASE = 'logsql62.sqlite'
LOCAL_MERGED_DATABASE = 'logsql_merged.sqlite'

REMOTE_HOST_STRUCTURE = '''CREATE TABLE IF NOT EXISTS hosts
                    (remote_host TEXT UNIQUE,
                    remote_country TEXT,
                    remote_country_code TEXT,
                    remote_latitude REAL,
                    remote_longitude REAL); '''
POPULATE_REMOTE_HOST = '''INSERT OR IGNORE INTO hosts (remote_host, remote_country, remote_country_code, remote_latitude, remote_longitude) VALUES (?,?,?,?,?)'''

DATA_CONNECTION = '''SELECT connection_protocol,
        datetime(connection_timestamp,'unixepoch','localtime') as connection_datetime,
        local_port,
        remote_host FROM connections
        WHERE connection_datetime BETWEEN '2015-10-01' AND '2015-10-31' '''
CONNECTION_STRUCTURE = '''CREATE TABLE IF NOT EXISTS connections 
                (connection_protocol TEXT,        
                connection_datetime TEXT,
                local_port INTEGER,
                remote_host TEXT);'''
POPULATE_CONNECTION = '''INSERT INTO connections VALUES (?,?,?,?)'''


DATA_SIP = '''SELECT 
    datetime(connections.'connection_timestamp','unixepoch') as connection_datetime,
    connections.connection_protocol,
    connections.local_port,
    sip_commands.sip_command_method,
    sip_commands.sip_command_user_agent,
    sip_commands.sip_command_allow,
    connections.remote_host
    FROM sip_commands 
    INNER JOIN connections on (sip_commands.connection=connections.connection)    
    WHERE connection_datetime BETWEEN '2015-10-01' AND '2015-10-31' '''
SIP_STRUCTURE = '''CREATE TABLE IF NOT EXISTS conn_sip
        (connection_timestamp TEXT,
        connection_protocl TEXT,
        local_port TEXT,
        sip_command_method,
        sip_command_user_agent,
        sip_command_allow INTEGER,
        remote_host TEXT); '''
POPULATE_SIP = "INSERT INTO conn_sip VALUES (?,?,?,?,?,?,?)"

DATA_DOWNLOADS = '''SELECT 
        downloads.download_md5_hash,
        datetime(connections.connection_timestamp,'unixepoch','localtime') as connection_datetime,
        connections.remote_host
        FROM connections
        INNER JOIN downloads ON (connections.connection = downloads.connection)
        WHERE connection_datetime BETWEEN '2015-10-01' AND '2015-10-31' '''
DOWNLOADS_STRUCTURE = '''CREATE TABLE IF NOT EXISTS conn_down 
                (download_md5_hash TEXT,
                connection_datetime TEXT,
                remote_host TEXT);'''        
POPULATE_DOWNLOADS = "INSERT INTO conn_down VALUES (?,?,?)"

DATA_MYSQL = '''SELECT datetime(connections.connection_timestamp,'unixepoch','localtime') datetime,
    mysql_command_args.mysql_command_arg_data,
    mysql_command_ops.mysql_command_op_name,
    connections.remote_host
    FROM connections
    INNER JOIN mysql_commands ON (mysql_commands.connection = connections.connection)
    INNER JOIN mysql_command_args ON (mysql_command_args.mysql_command = mysql_commands.mysql_command)
    INNER JOIN mysql_command_ops ON (mysql_command_ops.mysql_command_cmd = mysql_commands.mysql_command_cmd)
    WHERE datetime BETWEEN '2015-10-01' AND '2015-10-31' '''
MYSQL_STRUCTURE = '''CREATE TABLE IF NOT EXISTS conn_mysql 
        (connection_datetime TEXT,
        mysql_command_arg_data TEXT,
        mysql_command_op_name TEXT,
        remote_host TEXT);'''
POPULATE_MYSQL = "INSERT INTO conn_mysql VALUES (?,?,?,?)"

DATA_MSSQL = '''SELECT 
    datetime(connections.connection_timestamp,'unixepoch','localtime') as datetime,
    mssql_fingerprints.mssql_fingerprint_hostname,
    mssql_fingerprints.mssql_fingerprint_appname,
    mssql_fingerprints.mssql_fingerprint_cltintname,
    connections.remote_host
    FROM connections
    INNER JOIN mssql_fingerprints ON (mssql_fingerprints.connection = connections.connection)
    WHERE datetime BETWEEN '2015-10-01' AND '2015-10-31' '''
MSSQL_STRUCTURE = '''CREATE TABLE IF NOT EXISTS conn_mssql 
                (connection_datetime TEXT,
                mssql_fingerprint_hostname,
                mssql_fingerprint_appname,
                mssql_fingerprint_clientname,
                remote_host TEXT);'''
POPULATE_MSSQL = "INSERT INTO conn_mssql VALUES (?,?,?,?,?)"

DATA_VIRUSTOTAL = '''SELECT 
            virustotals.virustotal_md5_hash, 
            datetime(virustotals.virustotal_timestamp,'unixepoch','localtime') as datetime,
            virustotalscans.virustotalscan_result
        FROM virustotals
        INNER JOIN virustotalscans ON (virustotals.virustotal = virustotalscans.virustotal)
        WHERE (virustotalscans.virustotalscan_scanner LIKE 'kaspersky')  '''
VIRUSTOTAL_STRUCTURE = '''CREATE TABLE IF NOT EXISTS virust_scan
        (virustotal_md5_hash TEXT,
         virustotal_datetime TEXT,
         virustotal_result TEXT); '''
POPULATE_VIRUSTOTAL = "INSERT INTO virust_scan VALUES(?,?,?)"
         
DATA_MALWARE = '''select 
            download_md5_hash,
            virustotal_result,
            remote_host 
            from conn_down 
            LEFT JOIN virust_scan ON (download_md5_hash = virustotal_md5_hash) '''
MALWARE_STRUCTURE = '''CREATE TABLE IF NOT EXISTS down_virus 
        (download_md5_hash TEXT,
        virustotal_result TEXT,
        remote_host TEXT);'''
POPULATE_MALWARE = "INSERT INTO down_virus VALUES (?,?,?)"

DATA_IP_COUNTRIES = ''' select  DISTINCT count(connections.remote_host) , remote_country, conections.remote_host from connections
        INNER JOIN hosts ON (connections.remote_host like hosts.remote_host) 
        GROUP BY 
            connections.remote_host
        ORDER BY     
            COUNT(connections.remote_host) 
        DESC '''
IP_COUNTRIES_STRUCTURE = '''CREATE TABLE IF NOT EXISTS ipCountries
            (hits INTEGER,
            remote_country TEXT,
            remote_host TEXT);'''
POPULATE_IP_COUNTRIES = "INSERT INTO ipCountries VALUES (?,?,?) "

GLASTOPF_STRUCTURE = ''' CREATE TABLE IF NOT EXISTS glastopfs
        (remote_host TEXT,
        remote_country TEXT,
        date_time TEXT);'''

POPULATE_GLASTOPF = "INSERT INTO glastopfs VALUES (?,?,?)"
POPULATE_GLASTOPF_IP = "INSERT INTO glastopf_ip VALUES (?,?,?)"
POPULATE_GLASTOPF_COUNTRY = "INSERT INTO glastopf_country VALUES (?,?)"

DATA_WEB_HOST = '''SELECT DISTINCT remote_host FROM web_hosts'''


MONGO_STRUCTURE = '''CREATE TABLE IF NOT EXISTS conn_mongo 
                (connection_protocol TEXT,        
        connection_datetime TEXT,
                local_port INTEGER,
                remote_host TEXT);'''
POPULATE_MONGO = '''INSERT INTO conn_mongo VALUES (?,?,?,?)'''



DATA_COUNTRIES_CONNECTION = '''SELECT TOTAL(hits),remote_country 
            FROM ipCountries 
            GROUP by remote_country 
            ORDER BY TOTAL(hits) 
            DESC LIMIT 12'''

DATA_IP_CONNECTION = ''' select  DISTINCT count(remote_country), remote_country from ipcountries 
        GROUP BY 
            remote_country
        ORDER BY     
            COUNT(remote_country) 
        DESC '''

DATA_IP_DOWNLOADS = ''' select count(remote_host), remote_host, remote_country from conn_down 
        GROUP BY 
            remote_host
        ORDER BY     
            COUNT(remote_host) 
        DESC '''
DATA_COUNTRY_DOWNLOADS = ''' select count(remote_country), remote_country from conn_down 
        GROUP BY 
            remote_country
        ORDER BY     
            COUNT(remote_country) 
        DESC '''
DATA_PROTOCOLS = ''' select count(connection_protocol), connection_protocol, local_port  from conn_mongo 
        GROUP BY 
            connection_protocol
        ORDER BY     
            COUNT(connection_protocol) 
        DESC '''
DATA_HASH = '''select 
            virustotal_result,
            download_md5_hash
            from conn_down 
            LEFT JOIN virust_scan ON (download_md5_hash = virustotal_md5_hash)
            GROUP BY download_md5_hash'''
HASH_STRUCTURE = ''' CREATE TABLE IF NOT EXISTS top_hashes 
        (malware TEXT,
        hash TEXT);'''
POPULATE_HASH = "INSERT INTO top_hashes VALUES (?,?)"


DATA_GLASTOPF_IP = '''SELECT count(remote_host),remote_host,remote_country FROM glastopfs
    GROUP BY  remote_host
    ORDER BY count(remote_host) DESC'''

DATA_GLASTOPF_COUNTRY = '''SELECT count(remote_country),remote_country FROM glastopfs
    GROUP BY  remote_country
    ORDER BY count(remote_country) DESC'''





TOP_GLASTOPF_PATTERN_STRUCTURE = '''CREATE TABLE IF NOT EXISTS topGlastopfPatterns
        (no_of_attempts INTEGER,
         pattern TEXT);'''





COUNTRIES_CONNECTION_STRUCTURE = '''CREATE TABLE IF NOT EXISTS top_connection_countries
            (hits INTEGER, 
            country TEXT);'''


IP_CONNECTION_STRUCTURE = '''CREATE TABLE IF NOT EXISTS top_connection_ips
            (ips INTEGER,
            remote_country);'''

IP_DOWNLOADS_STRUCTURE = '''CREATE TABLE IF NOT EXISTS top_download_ips
            (downloads INTEGER,
            remote_host TEXT,
            remote_country TEXT);'''

COUNTRY_DOWNLOADS_STRUCTURE = '''CREATE TABLE IF NOT EXISTS top_download_countries
            (downloads INTEGER,
            remote_country TEXT);'''

PROTOCOLS_STRUCTURE = '''CREATE TABLE IF NOT EXISTS top_protocols
        (hits INTEGER,
         protocol TEXT,
        local_port TEXT);'''

                                        


P0F_STRUCTURE = '''CREATE TABLE IF NOT EXISTS p0f_mongo 
        (raw_sig TEXT, 
        os TEXT, 
        timestamp TEXT, 
        server_ip TEXT, 
        client_port INTEGER, 
        mod TEXT, 
        client_ip TEXT, 
        server_port INTEGER, 
        subject TEXT, 
        dist INTEGER, 
        parms TEXT,
        uptime TEXT,
        raw_freq TEXT);'''


GLASTOPF_IP_STRUCTURE = '''CREATE TABLE IF NOT EXISTS glastopf_ip
        (hits INTEGER,
         remote_host TEXT,
        remote_country TEXT);'''

GLASTOPF_COUNTRY_STRUCTURE = '''CREATE TABLE IF NOT EXISTS glastopf_country
        (hits INTEGER,
        remote_country TEXT);'''


POPULATE_MALWARE_NAME = "INSERT INTO kidoNames (no_of_malware, malware) VALUES (?,?)"

POPULATE_TOP_PROTOCOL = "INSERT INTO topProtocols (no_of_attempt, protocol, port) VALUES (?,?,?)"



POPULATE_UNKNOWN_HASH = "INSERT INTO unknownhashes (download_md5_hash, vulnerability_count, vulnerability_name, download_count ) VALUES (?,?,?,?)"


POPULATE_COUNTRIES_CONNECTION = "INSERT INTO top_connection_countries VALUES (?,?) "
POPULATE_IP_CONNECTION = "INSERT INTO top_connection_ips VALUES (?,?) "
POPULATE_IP_DOWNLOADS = "INSERT INTO top_download_ips VALUES(?,?,?)"
POPULATE_COUNTRY_DOWNLOADS = "INSERT INTO top_download_countries VALUES(?,?)"
POPULATE_PROTOCOLS = "INSERT INTO top_protocols VALUES(?,?,?)"


POPULATE_P0F = "INSERT INTO p0f_mongo VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"



def getDb():
    from pymongo import MongoClient
    client = MongoClient('115.186.132.20:27017')
    client.mnemosyne.authenticate('tiss', 'wud1991@WUD')
    #client = MongoClient('localhost',27017)
    db = client.mnemosyne
    #for d in cursor:
    #    print(d)      
    return db

def getMongo(db):
    print("In get mongo")
    start = datetime(2015, 8, 31)
    end = datetime(2015, 9, 30)
    cursor = db.session.find({ "$and":
                              [
                               { "timestamp":
                                ({ "$gte":start,
                                   "$lt": end
                                   })
                                },
                               { "honeypot":"dionaea"
                                },
                               { "source_ip":{ '$not':re.compile('115.186.176') #use of regix with not
                                              } 
                                }
                              ]
                            })
    for d in cursor:
        print(d)
    return cursor

def getMongop(db):
    start = datetime(2015, 8, 31)
    end = datetime(2015, 9, 30)
    cursor =db.hpfeed.find({ "$and":
                              [
                               { "timestamp":
                                ({ "$gte":start,
                                   "$lt": end
                                   })
                                },
                               { "channel":"p0f.events"
                                },
                               { "source_ip":{ '$not':re.compile('115.186.176') #use of regix with not
                                              } 
                                }
                              ]
                            }) 
    return cursor

def getMongog(db):
    cursor =db.session.find({"honeypot":"glastopf"})
    return cursor

#Generate the Country name base on the IP address
def getCountry(ipaddress):
        i=ipaddress.split('.')
        if (((i[0] == '10') or (i[0] == '172' and (i[1]>15 or i[1]<32)) or (i[0] == '192' and i[1] == '168')) or (ipaddress == '127.0.0.1') or (ipaddress == '100.70.158.92')  ):
            return "private"
        elif ipaddress == '103.54.248.249':
            return 'Vietnam','VNM',15.8,108.1167
        elif ipaddress == '103.55.88.13':
            return 'India','IND',20.0,77.0
        elif ipaddress == '138.118.125.2':
            return 'Panama','PAN',9.0,-80.0
        elif ipaddress == '103.55.36.43':
            return 'Indonesia','IDN',-1.2833,116.8333
        elif ipaddress == '185.108.196.178':
            return 'Russian Federation','RUS',52.0333,113.55
        elif ipaddress == '103.55.36.67':
            return 'Indonesia','IDN',-1.2833,116.8333
        elif ipaddress == '103.55.36.43':
            return 'Indonesia','IDN',-1.2833,116.8333
        elif ipaddress == '45.79.200.131':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '138.121.58.165':
            return 'Brazil','BRA',-25.55,-54.5833
        elif ipaddress == '45.79.9.231':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '103.54.200.227':
            return 'India','IND',31.3256,75.5792
        elif ipaddress == '138.185.177.230':
            return 'Brazil','BRA',-7.6833,-35.6667
        elif ipaddress == '138.186.95.238':
            return 'Brazil','BRA',-23.5477,-46.6358
        elif ipaddress == '138.121.182.226':
            return 'Brazil','BRA',-8.0217,-48.3786
        elif ipaddress == '45.115.16.101':
            return 'India','IND',23.0333,72.6167
        elif ipaddress == '185.103.245.183':
            return 'Iran','IRN',34.7336,46.6309 
        elif ipaddress == '103.55.104.140':
            return 'India','IND',28.4667,77.0333
        elif ipaddress == '138.204.73.192':
            return 'Brazil','BRA',-23.5477,-46.6358
        elif ipaddress == '185.103.244.210':
            return 'Iran','IRN',34.7336,46.6309
        elif ipaddress == '138.121.58.31':
            return 'Brazil','BRA',-25.55,-54.5833
        elif ipaddress == '45.79.204.224':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '103.56.164.31':
            return 'Vietnam','VNM',15.8,108.1167
        elif ipaddress == '45.117.156.61':
            return 'Vietnam','VNM',15.8,108.1167
        elif ipaddress == '185.106.120.170':
            return 'Netherlands','NLD',52.374,4.8897
        elif ipaddress == '45.79.75.171':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '103.58.124.131':
            return 'India','IND',20,77
        elif ipaddress == '103.61.90.138':
            return 'India','IND',20,77
        elif ipaddress == '45.122.52.62':
            return 'Hong Kong','HKG',22.3667,114.1333
        elif ipaddress == '45.122.52.144':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '45.79.173.215':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '185.95.154.67':
            return 'Iran','IRN',30.308,56.4217
        elif ipaddress == '103.193.18.4':
            return 'Pakistan','PAK',30,70
        elif ipaddress == '45.79.188.218':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '45.117.203.50':
            return 'India','IND',23.2406,87
        elif ipaddress == '45.122.52.144':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '45.122.52.144':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '45.122.52.144':
            return 'United States','USA',39.4899,-74.4773
        elif ipaddress == '45.122.52.144':
            return 'United States','USA',39.4899,-74.4773

        elif ipaddress == '169.254.159.216':
            return 'Unknown'
        else: 
            gi = pygeoip.GeoIP("GeoLiteCityt.dat");
            if "::ffff:" in ipaddress:
                ipaddress = ipaddress.split("::ffff:")
                ipaddress = ipaddress[1]
            gir = gi.record_by_name(ipaddress)
            if gir is None:
                print("In 2nd DB")
                gi = pygeoip.GeoIP("GeoLiteCity.dat");
                gir = gi.record_by_name(ipaddress)
            if gir is not None:
                return gir['country_name'],gir['country_code3'],gir['longitude'],gir['latitude']
            else:
                print(ipaddress, " not in Geolite DB")
                return 'unknown'
#Generate the Percentage of any column
def getPercentage(connection,table,column ):
    'This function return the percentage of the specific column basis on the record provided'
    total = connection.execute ("SELECT TOTAL(" +column+ ") FROM " +table )
    grand = 0.0
    for k in total:
        grand = str(k[0])
    return connection.execute ("SELECT ("+column+"*100)/"+ grand+ " FROM "+table)
    #return [rec for rec in per.fetchall()] 
  
#Get the Connection
def getConnection(database):
    'This function returns the connection'
    return sqlite3.connect(database)

#Provide the Cursor of the Database
def getCursor(database):
    'This function create Connections with the Database'
    #cu= sqlite3.connect(database).cursor().execute("SELECT count(request_url) FROM events WHERE request_url LIKE '%cgi-bin%'")
    #for dat in cu:
    #  print dat
    return sqlite3.connect(database).cursor()

# Connect to the Dionaea database to Insert specific records
def createTable(database, structure):
    'This function create the new table on the bases of Structure'
    getCursor(database).execute(structure)
    #table_name = 
    print "Table created Successfully"
  


#Connect to the logsql database and get the specific data
def getRecord(query, database):
    "This function will create a connection and store results"    
    cursor = getCursor(database)
    return cursor.execute(query)


#Add new Data columns to the table
def alterTable(database,table,column,datatype):
    'This function will create the percentage of the stuff you required'
    getCursor(database).execute("ALTER TABLE "+table+" ADD COLUMN "+column+" "+datatype)
    print "Column ",column, " has been created in ", table, " with datatype ",datatype

#Drop the Specific table
def dropTable(database,table):
    'This function provide a facility to drop any table'
    getCursor(database).execute("DROP TABLE " + table)
    print "Table",table,"Deleted Successfully"

#Update the record
def updateRecord(conn,table,column):
    'This Table Update the records'
    """data = getRecord('''update connections set remote_country = (
                            select h.remote_country 
                            from hosts h 
                            where h.remote_host  = connections.remote_host)'''
                    , LOCAL_MERGED_DATABASE)"""
    #data = getRecord("SELECT distinct local_port from conn_mongo where connection_protocol like 'pcap'", LOCAL_MERGED_DATABASE)
    data = getRecord("SELECT distinct remote_host from conn_mongo", LOCAL_MERGED_DATABASE)
    #column = 'percentage'
    
    for i in data:
        try:
            #query = "UPDATE " +table+ " SET " +column+ " = " +"(SELECT protocol from port_names where port = "+str(i[0])+") WHERE local_port = "+str(i[0])
            query = "UPDATE " +table+ " SET " +column+ " = " +"(SELECT remote_country from hosts where remote_country like ' "+str(i[0])+"') WHERE remote_host like '"+str(i[0])+"'"
            print(query)
            conn.execute(query)
        except Exception as e:
            print (e)
            break;
    conn.commit()
    print "Total rows updated", conn.total_changes 
  

def populateHosts(remote_host, connection, query):
    ipinfo = getCountry(remote_host)
    try:
        connection.cursor().execute(query, (remote_host, ipinfo[0], ipinfo[1], ipinfo[2], ipinfo[3]))
    except Exception as e:
        print(e)

def populateWebHosts(data, connection):
    for i in data:
        try:
            ipaddress = str(i[0])
            if "::ffff:" in str(i[0]):
                ipaddress = ipaddress.split("::ffff:")
                ipaddress = ipaddress[1]
            ipinfo = getCountry(ipaddress)
            #print(ipaddress, ipinfo[0], ipinfo[1], ipinfo[2], ipinfo[3])
            connection.cursor().execute(POPULATE_REMOTE_HOST, (ipaddress, ipinfo[0], ipinfo[1], ipinfo[2], ipinfo[3]))

        except Exception as e:
            print(e)
            break;
    connection.commit()
    
#Populate the Tables with the Data by Insertion
def populateTable(data, connection, query):
    'This function will populate the tables'
    #For Conn_Mongo
    if "INTO conn_mongo" in query:
        print("In Mongo Populate")
        for i in data:
            try:
                ipaddress = str(i['source_ip'])
                if "::ffff:" in str(i['source_ip']):
                    ipaddress = ipaddress.split("::ffff:")
                    ipaddress = ipaddress[1]
                
                populateHosts(ipaddress, connection, POPULATE_REMOTE_HOST)
                
                connection.cursor().execute(query, (i['protocol'], i['timestamp'], i['destination_port'], i['source_ip'] ))
            except Exception as e:
                print e
                break; 
    # For Connection, MYSQL
    elif "(?,?,?,?)" in query:
        for i in data:
            try:
                ipaddress = str(i[3])
                if "::ffff:" in str(i[3]):
                    ipaddress = ipaddress.split("::ffff:")
                    ipaddress = ipaddress[1]
                
                populateHosts(ipaddress, connection, POPULATE_REMOTE_HOST)
                connection.cursor().execute(query, (i[0], i[1], i[2], ipaddress))
            except Exception as e:
                print(e)
                break;
    # For SIP
    elif "(?,?,?,?,?,?,?)" in query:
        for i in data:
            try:
                #print(type(i[7]))
                ipaddress = i[6]
                if "::ffff:" in str(i[6]):
                    ipaddress = ipaddress.split("::ffff:")
                    ipaddress = ipaddress[1]
                    #print (i[0], i[1], i[2], i[3], i[4], i[5], i[6], ipaddress, getCountry(ipaddress), i[8] )
                connection.cursor().execute(query, (i[0], i[1], i[2], i[3], i[4], i[5], ipaddress ))
            except Exception as e:
                print(e)
                break;
    elif "INTO glastopfs" in query:
        for i in data:
            if "2015-09" in str(i['timestamp']):
                try:
                    connection.cursor().execute(query, (i['source_ip'],getCountry(i['source_ip'])[0],i['timestamp']))
                except Exception as e:
                    print (e)
                    break;
    # For downloads,Virustotal, malware,ipcountries
    elif "(?,?,?)" in query:
        print ('in 3')
        for i in data:
            try:
                ipaddress = i[2]
                if "::ffff:" in str(i[2]):
                    ipaddress = ipaddress.split("::ffff:")
                    ipaddress = ipaddress[1]
                print(i[0], i[1], ipaddress)
                connection.cursor().execute(query, (i[0], i[1], ipaddress))
            except Exception as e:
                print (e)
                break;
    
    # For MSSQL
    elif "(?,?,?,?,?)" in query:
        for i in data:
            try:
                ipaddress = i[4]
                if "::ffff:" in str(i[4]):
                    ipaddress = ipaddress.split("::ffff:")
                    ipaddress = ipaddress[1]
                connection.cursor().execute(query, (i[0], i[1], i[2], i[3] , ipaddress))
            except Exception as e:
                print e
                break;
        
    elif "INTO p0f_mongo" in query:
        for i in data:
            try:
                payload = ast.literal_eval(i["payload"])
                if('os' in payload): 
                    connection.cursor().execute(query, (payload['raw_sig'], payload['os'], payload['timestamp'], payload['server_ip'],payload['client_port'],payload['mod'],payload['client_ip'],payload['server_port'],payload['subject'],payload['dist'],payload['params'],"","" ))
                elif ('uptime' in payload):
                        connection.cursor().execute(query, ("", "", payload['timestamp'], payload['server_ip'],payload['client_port'],payload['mod'],payload['client_ip'],payload['server_port'],payload['subject'],"","",payload['uptime'],payload['raw_freq'] ))
            except Exception as e:
                print (e)
                break;

    elif "INTO down_virus" in query:
        print ('in malware')
        c=0
        for i in data:
            try:
                print( i[0],i[1],i[2],i[3] )
                connection.cursor().execute(query, (i[0],i[1],i[2],i[3]))
                c=c+1
                print("Inserted",c )
            except Exception as e:
                print (e)
                break;
    # For Virustotal
    elif "INTO virust_scan" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1], i[2], i[3]))
            except Exception as e:
                print (e)
                break;    
    elif "(?,?,?)" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1], i[2]))
            except Exception as e:
                print (e)
                break;
  
    elif "(?,?)" in query:
        for i in data:
            try:
                connection.cursor().execute(query, (i[0], i[1]))
            except Exception as e:
                print (e)
                break;
    connection.commit()
    #updateRecord(getConnection(LOCAL_DATABASE), "top10IPCountries" , "no_of_ip");
    print "Total rows updated", connection.total_changes
    print "Completed Loop"

#alterTable(LOCAL_DATABASE,"topConnectionCountries","percentage", "REAL");
#dropTable(LOCAL_MERGED_DATABASE,"glastopf_ip");
#dropTable(LOCAL_DATABASE,"topGlastopfs");
#dropTable(LOCAL_DATABASE,"topGlastopfPatterns");
#updateRecord(getConnection(LOCAL_MERGED_DATABASE), "conn_mongo", "connection_protocol") 
#updateRecord(getConnection(LOCAL_MERGED_DATABASE), "conn_mongo", "remote_country") 
#getPercentage(LOCAL_DATABASE,"topConnectionCountries","percentage");

createTable(LOCAL_MERGED_DATABASE,REMOTE_HOST_STRUCTURE);

createTable(LOCAL_MERGED_DATABASE,CONNECTION_STRUCTURE);
populateTable(getRecord(DATA_CONNECTION, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_CONNECTION);
populateTable(getRecord(DATA_CONNECTION, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_CONNECTION);
populateTable(getRecord(DATA_CONNECTION, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_CONNECTION);

#createTable(LOCAL_MERGED_DATABASE,SIP_STRUCTURE);
#populateTable(getRecord(DATA_SIP, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_SIP);
#populateTable(getRecord(DATA_SIP, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_SIP);
#populateTable(getRecord(DATA_SIP, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_SIP);

#createTable(LOCAL_MERGED_DATABASE,DOWNLOADS_STRUCTURE);
#populateTable(getRecord(DATA_DOWNLOADS, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_DOWNLOADS);
#populateTable(getRecord(DATA_DOWNLOADS, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_DOWNLOADS);
#populateTable(getRecord(DATA_DOWNLOADS, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_DOWNLOADS);

#createTable(LOCAL_MERGED_DATABASE,MYSQL_STRUCTURE);
#populateTable(getRecord(DATA_MYSQL, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MYSQL);
#populateTable(getRecord(DATA_MYSQL, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MYSQL);
#populateTable(getRecord(DATA_MYSQL, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MYSQL);

#createTable(LOCAL_MERGED_DATABASE,MSSQL_STRUCTURE);
#populateTable(getRecord(DATA_MSSQL, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MSSQL)
#populateTable(getRecord(DATA_MSSQL, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MSSQL)
#populateTable(getRecord(DATA_MSSQL, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MSSQL)

#createTable(LOCAL_MERGED_DATABASE,VIRUSTOTAL_STRUCTURE );
#populateTable(getRecord(DATA_VIRUSTOTAL, PUBLIC19_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_VIRUSTOTAL);
#populateTable(getRecord(DATA_VIRUSTOTAL, PUBLIC21_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_VIRUSTOTAL);
#populateTable(getRecord(DATA_VIRUSTOTAL, PUBLIC62_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_VIRUSTOTAL);

#createTable(LOCAL_MERGED_DATABASE,IP_COUNTRIES_STRUCTURE );
#populateTable(getRecord(DATA_IP_COUNTRIES, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_IP_COUNTRIES);

#createTable(LOCAL_MERGED_DATABASE,MALWARE_STRUCTURE );
#populateTable(getRecord(DATA_MALWARE, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MALWARE);
#populateWebHosts(getRecord(DATA_WEB_HOST, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE));


if __name__ == "__main__":
    db = getDb()
    #getMongo(db)
    #print(getCountry('111.68.99.39'))
    
    #createTable(LOCAL_MERGED_DATABASE,MONGO_STRUCTURE);
    #populateTable(getMongo(db), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MONGO);
    #getRecord('''DELETE FROM conn_mongo WHERE remote_host like "172.20.16.%" ''',LOCAL_MERGED_DATABASE)        
    
    
    #createTable(LOCAL_MERGED_DATABASE,P0F_STRUCTURE);
    #populateTable(getMongop(db), getConnection(LOCAL_MERGED_DATABASE), POPULATE_P0F);

    #createTable(LOCAL_MERGED_DATABASE,GLASTOPF_STRUCTURE);
    #populateTable(getMongog(db), getConnection(LOCAL_MERGED_DATABASE), POPULATE_GLASTOPF);

    #createTable(LOCAL_MERGED_DATABASE,GLASTOPF_IP_STRUCTURE);
    #populateTable(getRecord(DATA_GLASTOPF_IP, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_GLASTOPF_IP);

    #createTable(LOCAL_MERGED_DATABASE,GLASTOPF_COUNTRY_STRUCTURE);
    #populateTable(getRecord(DATA_GLASTOPF_COUNTRY, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_GLASTOPF_COUNTRY);
  
    #createTable(LOCAL_MERGED_DATABASE,IP_COUNTRIES_STRUCTURE );
    #populateTable(getRecord(DATA_IP_COUNTRIES, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_IP_COUNTRIES);
  
  
    #createTable(LOCAL_MERGED_DATABASE,COUNTRIES_CONNECTION_STRUCTURE );
    #populateTable(getRecord(DATA_COUNTRIES_CONNECTION, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_COUNTRIES_CONNECTION);
  
    #createTable(LOCAL_MERGED_DATABASE,IP_CONNECTION_STRUCTURE );
    #populateTable(getRecord(DATA_IP_CONNECTION, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_IP_CONNECTION);
  
    #createTable(LOCAL_MERGED_DATABASE,IP_DOWNLOADS_STRUCTURE );
    #populateTable(getRecord(DATA_IP_DOWNLOADS, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_IP_DOWNLOADS);
  
    #createTable(LOCAL_MERGED_DATABASE,COUNTRY_DOWNLOADS_STRUCTURE );
    #populateTable(getRecord(DATA_COUNTRY_DOWNLOADS, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_COUNTRY_DOWNLOADS);
  
    #createTable(LOCAL_MERGED_DATABASE,PROTOCOLS_STRUCTURE );
    #populateTable(getRecord(DATA_PROTOCOLS, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_PROTOCOLS);

    #createTable(LOCAL_MERGED_DATABASE,HASH_STRUCTURE );
    #populateTable(getRecord(DATA_HASH, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_HASH);

    #createTable(LOCAL_MERGED_DATABASE,MALWARE_STRUCTURE );
    #populateTable(getRecord(DATA_MALWARE, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_MALWARE);

    #createTable(LOCAL_MERGED_DATABASE,  IP_LOCATION_STRUCTURE);
    #populateTable(getRecord(DATA_IP_LOCATION, LOCAL_MERGED_DATABASE), getConnection(LOCAL_MERGED_DATABASE), POPULATE_IP_LOCATION);
    