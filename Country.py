'''
Created on Aug 19, 2015

@author: waseem
'''



import GeoIP
def getCountry(ipaddress):
        i=ipaddress.split('.')
        if ((i[0] == '10') or (i[0] == '172' and (i[1]>15 or i[1]<32)) or (i[0] == '192' and i[1] == '168')  ):
            return "private"
        elif ((i[0] == '169') and (i[1] == '254') and (i[2]>'0' or i[2]<'254')):
            return 'Microsoft'
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
                report = gir["country_code"] ,gir["country_name"]
                return report
            else:
                print(ipaddress, " not in Geolite DB")
    
print (getCountry("202.120.222.114"))


