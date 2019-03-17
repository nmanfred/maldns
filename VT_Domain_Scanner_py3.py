# Based on VT Domain Scanner: https://github.com/clairmont32/VirusTotal-Tools/blob/master/VT_Domain_Scanner_py3.py
# If you have a private API key, you can change the sleep times to 1 for faster scanning

import time
import requests
import csv
import os
import config
from db_utils import create_connection

def getDirtyDomain(domain):
    # unsanitize domain
    return domain.replace('[.]', '.')

# scan the domain to ensure results are fresh
def DomainScanner(domain, client):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    domainDirty = getDirtyDomain(domain)
    params = {'apikey': config.apikey, 'url': domainDirty}
    delay = {}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is not 1:
                print('There was an error submitting the domain for scanning.')
                print(jsonResponse['verbose_msg'])
            elif jsonResponse['response_code'] == -2:
                print('{!s} is queued for scanning.'.format(domain))
                delay[domain] = 'queued'
            else:
                print('{!s} was scanned successfully.'.format(domain))

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domain))
            domainErrors.append(domain) # XXX

        # return domain errors for notifying user when script completes
        time.sleep(15)  ############### IF YOU HAVE A PRIVATE ACCESS YOU CAN CHANGE THIS TO 1 ###################
        return delay

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')


def DomainReportReader(domain, delay, client):
    # sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold,
    # you WILL get a warning email to the owner of the account if you exceed this limit.
    # Private API allows for tiered levels of queries/second.

    # check to see if we have a delay in the report being available
    # if we do, delay for a little bit longer in hopes of the report being ready
    if delay:
        if domain in delay:
            time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': config.apikey, 'resource': getDirtyDomain(domain)}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)
        exit(1)
    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is 0:
                print('There was an error submitting the domain for scanning.')
                pass

            elif jsonResponse['response_code'] == -2:
                print('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domain))

            else:
                print('Report is ready for', domain)

            # print(jsonResponse)
            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            data = [scandate, domain, positives, total, permalink]
            return data

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domain))
            domainErrors.append(domain)

        except KeyError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domain))
            domainErrors.append(domain)

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
        time.sleep(10)
        DomainReportReader(domain, delay)

def scan_expired_or_unscanned_domains(conn):
    try:
        requests.urllib3.disable_warnings()
        client = requests.session()
        client.verify = False
        domainErrors = []
        delay = {}

        c = conn.cursor()
        c.execute('SELECT * FROM dns_queries WHERE last_scan IS NULL OR last_scan = \'\';')
        new_rows = c.fetchall()
        c.close()

        for row in new_rows:
            domain = row[2]

            try:
                delay = DomainScanner(domain, client)
                data = DomainReportReader(domain, delay, client)

                c = conn.cursor()
                c.execute('UPDATE dns_queries SET last_scan=?,num_positive=?,total_scans=?,permalink=? WHERE url=?;',(data[0], data[2], data[3], data[4], domain))
                conn.commit()
                c.close()

                time.sleep(15)  # wait for VT API rate limiting
            except Exception as err:  # keeping it
                print('Encountered an error but scanning will continue.', err)
                pass

    except Exception as e:
       print(e)

def vt_lookup():
    conn = create_connection("./maldns.db")
    if conn == None:
        sys.exit(1)
    scan_expired_or_unscanned_domains(conn)

