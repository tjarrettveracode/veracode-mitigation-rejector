import argparse
import logging
import datetime
import json
from uuid import UUID
import anticrlf
from beautifultable import BeautifulTable

from veracode_api_py import VeracodeAPI as vapi, Applications, Findings

log = logging.getLogger(__name__)
app_names = list()

def setup_logger():
    handler = logging.FileHandler('vcmitreject.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone()
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def is_valid_datetime(string_to_test):
    try:
        datetime.datetime.strptime(string_to_test,'%Y-%m-%d')
    except ValueError:
        raise ValueError("Incorrect data format, should be YYYY-MM-DD")
    return True

def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def prompt_for_app(prompt_text):
    appguid = ""
    app_name_search = input(prompt_text)
    app_candidates = vapi().get_app_by_name(app_name_search)
    if len(app_candidates) == 0:
        print("No matches were found!")
    elif len(app_candidates) > 1:
        print("Please choose an application:")
        for idx, appitem in enumerate(app_candidates,start=1):
            print("{}) {}".format(idx, appitem["profile"]["name"]))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(app_candidates):
                appguid = app_candidates[int(i)-1].get('guid')
        except ValueError:
            appguid = ""
    else:
        appguid = app_candidates[0].get('guid')
    return appguid    

def get_apps_list(appguid=None,new_since=None):
    the_apps=[]
    
    # only look at new_since if appguid not specified
    if appguid:
        the_apps.append(appguid)
    elif new_since:
        matching_apps = Applications().get_all(policy_check_after=new_since)
        matching_app_guids = [ma['guid'] for ma in matching_apps]
        the_apps.extend(matching_app_guids)

    return the_apps

def get_all_app_findings(the_apps,new_since=None):
    the_findings=[]
    for app in the_apps:
        request_params = {}
        if new_since:
            request_params['mitigated_after'] = new_since

        these_findings = Findings().get_findings(app=app, scantype='ALL', annot=True, request_params=request_params)

        these_mitigated_findings = get_self_mitigated_findings(these_findings)
        status = "Found {} mitigated out of {} total findings for application {}".format(len(these_mitigated_findings),len(these_findings),app)
        print(status)
        log.info(status)

        # these_findings find the findings that have .action = 'APPROVED' and .action != APPROVED, COMMENT, REJECTED with same user

        the_findings.extend(these_mitigated_findings)

    return the_findings

def find_approver(the_finding):
    return next((annot['user_name'] for annot in the_finding['annotations'] if annot['action'] == 'APPROVED'),"")

def find_proposer(the_finding):
    return next((annot['user_name'] for annot in the_finding['annotations'] if annot['action'] in ('APPDESIGN','FP','NETENV','OSENV','LIBRARY','ACCEPTRISK')),"") 

def get_self_mitigated_findings(all_findings):
    # start by getting all mitigated findings
    mitigated_findings = list(filter(lambda finding: finding['finding_status']['resolution_status'] == 'APPROVED', all_findings))

    self_mitigated_findings=[]
    
    for each_finding in mitigated_findings: # ideally we want to do this with list comprehension, but looping through as a first pass
        approver = find_approver(each_finding)
        proposer = find_proposer(each_finding)
        if proposer == approver and approver != "":
            self_mitigated_findings.append(each_finding)

    return self_mitigated_findings

def get_app_name(app_guid):
    app_name = next((app['name'] for app in app_names if app['guid'] == app_guid),"")
    if app_name == "":
        the_app = Applications().get(guid=app_guid)
        app_name = the_app['profile']['name']
        app_names.append({'guid':app_guid,'name':app_name})
    return app_name

def build_report(the_findings):
    table = BeautifulTable(maxwidth=100)
    for each_finding in the_findings:
        this_guid = each_finding['context_guid']
        app_name = get_app_name(app_guid=this_guid)
        table.rows.append([each_finding['issue_id'],app_name,this_guid,each_finding['scan_type'],each_finding['finding_details']['cwe']['id'],find_approver(each_finding)])

    table.columns.header = ['Flaw ID','App Name','App GUID','Scan Type','CWE ID','Approver']
    table.columns.header.alignment = BeautifulTable.ALIGN_CENTER
    table.columns.alignment['App Name'] = BeautifulTable.ALIGN_LEFT
    table.columns.alignment['App GUID'] = BeautifulTable.ALIGN_LEFT
    table.columns.alignment['Approver'] = BeautifulTable.ALIGN_LEFT
    table.set_style(BeautifulTable.STYLE_COMPACT)
    print()
    print(table)
    #format findings list


def reject_self_mitigated_findings(the_findings):
    rejection_comment = 'Automatically rejecting self-approved mitigation.'

    for each_finding in the_findings:
        issue_id = each_finding['issue_id']
        app_guid = each_finding['context_guid']
        Findings().add_annotation(app=app_guid, issue_list=[issue_id],comment=rejection_comment,action='REJECTED')
        log.info('Rejected mitigation for issue {} on app guid {}'.format(issue_id,app_guid))


def main():
    parser = argparse.ArgumentParser(
        description='This script identifies and, optionally, rejects self-approved mitigations.')
    parser.add_argument('-a', '--app_id', help='Applications guid to check for self-approved mitigations.')
    parser.add_argument('-p', '--prompt', action='store_true', help='Prompt for application using partial match search.')
    parser.add_argument('-n', '--new_since', help='Check for new self-approved mitigations after the date-time provided.')
    parser.add_argument('-r', '--reject', action='store_true', help='Attempt to automatically reject self-approved mitigations.')
    args = parser.parse_args()

    appguid = args.app_id
    new_since = args.new_since
    reject = args.reject
    prompt = args.prompt

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # validate inputs
    if not(new_since) and not(prompt) and not (appguid):
        print('Searching across all applications in your account. This may take some time…')

    if new_since:
        if not(is_valid_datetime(new_since)):
            print('{} is an invalid datetime value. Please provide the date in YYYY-MM-DDTHH:MM:SS.OOOZ format'.format(new_since))
            return
    else:
        new_since = '2006-04-01' #fetch data for all time

    if prompt: 
        appguid = prompt_for_app('Enter the application name for which to reject self-approved mitigations: ')

    if appguid and not(is_valid_uuid(appguid)):
        print('{} is an invalid application guid. Please supply a valid UUID.'.format(appguid))
        return

    # get apps to test
    apps = []
    apps = get_apps_list(appguid, new_since)        

    if len(apps) == 0:
        print("No applications found that match the specified parameters.")
        return 0

    print('Checking {} applications for self mitigated findings.'.format(len(apps)))

    # get findings for apps
    all_findings = get_all_app_findings(apps,new_since)
    print('{} self-mitigated findings found within the criteria provided.'.format(len(all_findings)))
    if len(all_findings) == 0:
        return

    # construct report
    build_report(all_findings)

    # reject self-approved mitigations
    if reject:
        reject_self_mitigated_findings(all_findings)
        print('Rejected {} self-mitigated findings'.format(len(all_findings)))

if __name__ == '__main__':
    main()