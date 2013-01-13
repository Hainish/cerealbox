import pygeoip
from incf.countryutils import transformations

gi = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat')

def lookup(ip):
  country_code = gi.country_code_by_addr(ip)
  continent = transformations.cca_to_ctca2(country_code)
  return (country_code, continent)
