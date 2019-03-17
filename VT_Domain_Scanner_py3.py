# Based on VT Domain Scanner: https://github.com/clairmont32/VirusTotal-Tools/blob/master/VT_Domain_Scanner_py3.py
# If you have a private API key, you can change the sleep times to 1 for faster scanning

import time
import requests
import csv
import os
import config
import logging
from db_utils import create_connection

def virustotal_rate_limit():
    if config.private_access:
        time.sleep(1)
    else:
        time.sleep(15)

def getDirtyDomain(domain):
    # unsanitize domain
    return domain.replace('[.]', '.')

# scan the domain to ensure results are fresh
def DomainScanner(domain, client, should_report):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    domainDirty = getDirtyDomain(domain)
    params = {'apikey': config.apikey, 'url': domainDirty}
    delay = {}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        logging.warning('Connection timed out. Error is as follows-')
        logging.warning(timeout)

    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # log error if the scan had an issue
            if jsonResponse['response_code'] is not 1:
                logging.warning('There was an error submitting the domain {} for scanning.'.format(domain))
                logging.warning(jsonResponse['verbose_msg'])
            elif jsonResponse['response_code'] == -2: # XXX - should report?
                logging.info('{!s} is queued for scanning.'.format(domain))
                delay[domain] = 'queued'
            else:
                logging.info('{!s} was scanned successfully.'.format(domain))
                should_report = True

        except ValueError:
            logging.warning('There was an error when scanning {!s}.'.format(domain))
            should_report = False


    # API TOS issue handling
    elif r.status_code == 204:
        logging.warning('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        logging.warning('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')

    # return domain errors for notifying user when script completes
    virustotal_rate_limit()

    return (delay, should_report)


def DomainReportReader(domain, delay, client, should_report):
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
        logging.error('Connection timed out. Error is as follows-')
        logging.error(timeout)
        exit(1)
    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # log error if the scan had an issue
            if jsonResponse['response_code'] is 0:
                logging.warning('There was an error submitting the domain {} for scanning.'.format(domain))
                pass

            elif jsonResponse['response_code'] == -2: # XXX should_report?
                logging.warning('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domain))

            else:
                logging.info('Report is ready for {}'.format(domain))
                should_report = True

            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            data = [scandate, domain, positives, total, permalink]

        except ValueError:
            logging.warning('There was an error when scanning {!s}.'.format(domain))
            should_report = False

        except KeyError:
            logging.warning('There was an error when scanning {!s}.'.format(domain))
            should_report = False

    # API TOS issue handling
    elif r.status_code == 204:
        logging.warning('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        logging.warning('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
        time.sleep(10)
        data, should_report = DomainReportReader(domain, delay, client, should_report)
    
    return (data, should_report)

def scan_expired_or_unscanned_domains(conn):
    try:
        requests.urllib3.disable_warnings()
        client = requests.session()
        client.verify = False
        delay = {}

        c = conn.cursor()
        c.execute('SELECT * FROM dns_queries WHERE last_scan IS NULL OR last_scan = \'\';')
        new_rows = c.fetchall()
        c.close()

        for row in new_rows:
            domain = row[2]

            try:
                should_report = False
                delay, should_report = DomainScanner(domain, client, should_report)
                if should_report:
                    should_report = False
                    data, should_report = DomainReportReader(domain, delay, client, should_report)

                    c = conn.cursor()
                    if should_report:
                        c.execute('UPDATE dns_queries SET last_scan=?,num_positive=?,total_scans=?,permalink=? WHERE url=?;',(data[0], data[2], data[3], data[4], domain))
                        conn.commit()
                c.close()

                virustotal_rate_limit()
            except Exception as err:  # keeping it
                logging.warning('Encountered an error but scanning will continue.', err)
                pass

    except Exception as e:
       logging.warning(e)

def vt_lookup():
    conn = create_connection("./maldns.db")
    if conn == None:
        logging.error("No database connection, exiting.")
        sys.exit(1)

    while True:
        scan_expired_or_unscanned_domains(conn)

    logging.info("Done scanning")
