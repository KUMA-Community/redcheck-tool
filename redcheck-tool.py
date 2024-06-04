import csv
import re
import json
import requests
import argparse
import sys

#hide InsecureRequestWarning
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

parser=argparse.ArgumentParser()
parser.add_argument('--kuma-rest', type=str, help='Provide kuma-core ip address and port. Example: 10.0.0.1:7223', required=True)
parser.add_argument('--token', type=str, help='Provide API token. User must have permission for GET /assets, GET /tenants, POST /assets/import', required=True)
parser.add_argument('--tenant', type=str, help='Provide Tenant name', required=True)
parser.add_argument('--vuln-report', type=str, help='Provide path to vulnerability report', required=True)
parser.add_argument('--inventory-report', type=str, help='(Optional) Provide path to inventory report', required=False, default='')
parser.add_argument('-v', help='(Optional) Verbose output', action='store_true', default=False)

args = parser.parse_args()
#number of vulns with description, do not increase
border = 50
#array for other vulns CVEs
otherVulns=[]
#inventory, software, vulnerabilities
totals={'inventory':0, 'software':0, 'vulnerabilities':0}

KUMA_API = args.kuma_rest
vulns = args.vuln_report
prods = args.inventory_report
tenantName = args.tenant
token = args.token
verbose=args.v

#map redcheck severity to kuma
severity={"Недоступно":0,"Низкий":1, "Средний":2, "Высокий":3, "Критический":3}
#map redchek software attribute names to kuma
productKeys={"Версия":"version", "Издатель":"vendor"}

KUMAtenantURL = 'https://' + KUMA_API + '/api/v1/tenants'
KUMAsearchURL = 'https://' + KUMA_API + '/api/v1/assets'
KUMAimportURL = KUMAsearchURL + '/import'
headers={'Authorization': 'Bearer ' + token ,'Content-Type': 'application/json'}
#get tenant id by name
r=requests.get(KUMAtenantURL, headers=headers, verify=False, params={"name":tenantName})
response = r.json()

if (r.status_code!=200):
    sys.exit(f"Tenant search error: Unexpected status Code: {r.status_code}")

if (len(response)==0):
    sys.exit(f"Tenant \"{tenantName}\" not found")

tenantID=response[0]['id']

def sendAsset(asset, type):
    typeMap={'vulnerabilities':'software', 'software':'vulnerabilities', 'inventory':'inventory'}
    if('fqdn' in asset.keys()):
        r=requests.get(KUMAsearchURL, headers=headers, verify=False, params={"fqdn":asset['fqdn']})
    elif('ipAddresses' in asset.keys()):
        r=requests.get(KUMAsearchURL, headers=headers, verify=False, params={"ip":asset['ipAddresses'][0]})
    else:
        return 0
    
    if(r.status_code!=200):
        sys.exit(f"Asset search error: Unexpected status Code: {r.status_code}")

    kumaAsset = r.json()

    if (len(kumaAsset)!=0):
        if(type!='inventory'):
            asset.update({'name':kumaAsset[0]['name'],'fqdn':kumaAsset[0]['fqdn'],'ipAddresses':kumaAsset[0]['ipAddresses'],'macAddresses':kumaAsset[0]['macAddresses'],'owner':kumaAsset[0]['owner'], 'os':kumaAsset[0]['os'], typeMap[type]:kumaAsset[0][typeMap[type]]}) 
        else:
            asset.update({'name':kumaAsset[0]['name']})
            if('fqdn' not in asset.keys()):
                asset.update({'fqdn':kumaAsset[0]['fqdn']})
            if('ipAddresses' in asset.keys() and len(kumaAsset[0]['ipAddresses'])!=0):
                for ip in kumaAsset[0]['ipAddresses']:
                    if (ip not in asset['ipAddresses']):
                        asset['ipAddresses'].append(ip)
            if('ipAddresses' not in asset.keys()):
                asset.update({'ipAddresses':kumaAsset[0]['ipAddresses']})
            if('macAddresses' in asset.keys() and len(kumaAsset[0]['macAddresses'])!=0):
                for mac in kumaAsset[0]['macAddresses']:
                    if (mac not in asset['macAddresses']):
                        asset['macAddresses'].append(mac)
            if('macAddresses' not in asset.keys()):
                asset.update({'macAddresses':kumaAsset[0]['macAddresses']})
    #exclude localhost and 127.0.0.1
    if(('fqdn' in asset.keys() and asset['fqdn']=='localhost') or ('ipAddresses' in asset.keys() and '127.0.0.1' in asset['ipAddresses'])):
        if verbose:
            print("{0:<32} {1:<32} {2}".format(f"[{type} import][error]", f"Host: {asset['name']}", f"Skipped asset with FQDN localhost or IP 127.0.0.1"))
    else:       
        r=requests.post(KUMAimportURL, data=json.dumps({'tenantID':tenantID, 'assets':[asset]}),headers=headers, verify=False)
        if r.status_code==200:
            totals[type]+=1
        if verbose:
            print("{0:<32} {1:<32} {2:<10} {3}".format(f"[{type} import]", f"Host: {asset['name']}", f"Code: {r.status_code}", f"Response: {r.json()}"))
    
if (len(prods)!=0):    
    #gather network information
    asset={'name':''}
    with open(prods, encoding="utf-8-sig") as csvfile:
        csvReader=csv.DictReader(csvfile, delimiter=',')
        for row in csvReader:
            if(row['Категория (Уровень 2)']=='Сетевые адаптеры'):
                if (asset['name']!=row['Хост']):
                    if(len(asset['name'])!=0):
                        sendAsset(asset, 'inventory')                        
                    if bool(re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", row['Хост'])):
                        asset.pop('fqdn', None)
                        asset.update({'name':row['Хост'], 'ipAddresses':[row['Хост']]})
                    else:
                        asset.pop('ipAddresses', None)
                        asset.update({'name':row['Хост'], 'fqdn':row['Хост']})
                if (row['Категория (Уровень 2)']=='Сетевые адаптеры'):
                    if (row['Категория (Уровень 4)']=='IP-адреса' and row['Параметр']=='IP'):
                        if('ipAddresses' not in asset.keys()):
                            asset.update({"ipAddresses":[]})
                        if(row['Значение'] not in asset['ipAddresses']):
                            asset['ipAddresses'].append(row['Значение'])
                    if (row['Параметр']=='MAC-адрес'):
                        if('macAddresses' not in asset.keys()):
                            asset.update({"macAddresses":[]})
                        asset['macAddresses'].append(row['Значение'])
                    if (row['Параметр']=='Имя DNS-хоста'):
                        asset.update({"fqdn":row['Значение']})
        sendAsset(asset, 'inventory')
 
    #gather software information
    asset={'name':''}
    with open(prods, encoding="utf-8-sig") as csvfile:   
        csvReader=csv.DictReader(csvfile, delimiter=',')
        for row in csvReader:
            if(row['Категория (Уровень 2)']=='Установленное ПО'):
                if (asset['name']!=row['Хост']):
                    if(len(asset['name'])!=0):
                        sendAsset(asset, 'software')
                    if bool(re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", row['Хост'])):
                        asset.pop('fqdn', None)
                        asset.update({'name':row['Хост'], 'ipAddresses':[row['Хост']], 'software':[]})
                    else:
                        asset.pop('ipAddresses', None)
                        asset.update({'name':row['Хост'], 'fqdn':row['Хост'], 'software':[]})
                if (row['Параметр']=='Имя'):
                    productName=row['Значение']
                    asset['software'].append({"name":productName})
                if (row['Параметр'] in productKeys and len(asset['software'])!=0):
                    asset['software'][len(asset['software'])-1].update({productKeys[row['Параметр']]:"[" + row['Значение'] + "]"})
        sendAsset(asset, 'software')

#gather vulnerability information
with open(vulns, encoding="utf-8-sig") as csvfile:
    asset={'name':''}
    csvReader=csv.DictReader(csvfile, delimiter=',')
    for row in csvReader:
        if (asset['name']!=row['Хост']):
            if(len(asset['name'])!=0):
                if(len(otherVulns)!=0):
                    asset['vulnerabilities'].append({"productName":"Other Vulnerabilities", "cve":otherVulns})  
                sendAsset(asset, 'vulnerabilities')
                otherVulns=[]
            if bool(re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", row['Хост'])):
                asset.pop('fqdn', None)
                asset.update({'name':row['Хост'], 'ipAddresses':[row['Хост']], 'vulnerabilities':[]})
            else:
                asset.pop('ipAddresses', None)
                asset.update({'name':row['Хост'], 'fqdn':row['Хост'], 'vulnerabilities':[]})
        if(len(asset['vulnerabilities']) <= border):
            asset['vulnerabilities'].append({"productName":row['Продукты'], "descriptionURL":row['Cve Url'], "severity":severity[row['Критичность']], "cve":[row['CveId']]})
        else:
            otherVulns.append(row['CveId'])
    if(len(otherVulns)!=0):
        asset['vulnerabilities'].append({"productName":"Other Vulnerabilities", "cve":otherVulns})       
    sendAsset(asset, 'vulnerabilities')
    otherVulns=[]

for key in totals:
    print(f'{key} has been imported for {totals[key]} host(s)')
