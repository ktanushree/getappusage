#!/usr/bin/env python
"""
Prisma SDWAN script to get app usage. This script lists the policy sets, rules and sites the policy sets are attached to

tkamath@paloaltonetworks.com

"""
import pandas as pd
import os
import sys
import yaml
from netaddr import IPAddress, IPNetwork
from random import *
import argparse
import logging
import datetime
import prisma_sase


# Global Vars
SDK_VERSION = prisma_sase.version
SCRIPT_NAME = 'Prisma SDWAN: Get App Usage'


# Policy Types
SECURITY_POL ="security"
NW_STACK = "nwstack"
QOS_STACK = "qosstack"
NAT_STACK = "natstack"
NGFW_STACK = "ngfwstack"
PERF_STACK = "perfstack"
ORIGINAL = "original"
BOUND = "BOUND"
ALL = "ALL"
ALL_APPS = "ALL_APPS"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

#
# Service Account Details
#
try:
    from prismasdwan_settings import PRISMASDWAN_CLIENT_ID, PRISMASDWAN_CLIENT_SECRET, PRISMASDWAN_TSG_ID
    import prisma_sase

except ImportError:
    # will get caught below
    PRISMASDWAN_CLIENT_ID = None
    PRISMASDWAN_CLIENT_SECRET = None
    PRISMASDWAN_TSGID = None


# Global Translation Dicts
siteid_nwstackid = {}
siteid_nwpolid = {}
siteid_qosstackid = {}
siteid_natstackid = {}
siteid_secpolid = {}
siteid_sitename = {}
sitename_siteid = {}
appname_appid = {}
appid_appname = {}
polname_polid = {}
polid_polname = {}
nwstackid_policysetlist = {}
nwstackname_nwstackid = {}
nwstackid_nwstackname = {}
qosstackid_policysetlist = {}
qosstackname_qosstackid = {}
qosstackid_qosstackname = {}
natstackid_policysetlist = {}
natstackname_natstackid = {}
natstackid_natstackname = {}
secpolname_secpolid = {}
secpolid_secpolname = {}
nwpolname_nwpolid = {}
nwpolid_nwpolname = {}
qospolname_qospolid = {}
qospolid_qospolname = {}
natpolname_natpolid = {}
natpolid_natpolname = {}
nwpolid_nwruleslist = {}
qospolid_qosruleslist = {}
natpolid_natruleslist = {}
polid_polruleslist = {}
secpolid_secruleslist = {}

ngfwstackid_policysetlist={}
ngfwstackname_ngfwstackid = {}
ngfwstackid_ngfwstackname = {}
ngfwpolname_ngfwpolid = {}
ngfwpolid_ngfwpolname = {}

perfstackid_policysetlist={}
perfstackname_perfstackid = {}
perfstackid_perfstackname = {}
perfpolname_perfpolid = {}
perfpolid_perfpolname = {}


def create_dicts(cgx_session, appname):

    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        applist = resp.cgx_content.get("items",None)
        for app in applist:
            appname_appid[app["display_name"]] = app["id"]
            appid_appname[app["id"]] = app["display_name"]

    else:
        print("ERR: Could not retrieve appdefs")
        cloudgenix.jd_detailed(resp)

    #
    # Validate App Name before querying for other resources
    #
    appidlist = []
    if appname in appname_appid.keys():
        appidlist = [appname_appid[appname]]
        print("Getting data for: {}".format(appname))

    else:
        if appname == ALL_APPS:
            appidlist = appid_appname.keys()
            print("Getting data for: {}".format(appname))

        else:
            print("ERR: Invalid App Name")
            clean_exit(cgx_session)


    #
    #Sites
    #
    print("\tSites")
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items",None)

        for site in sitelist:
            sid = site["id"]
            siteid_sitename[sid] = site["name"]
            sitename_siteid[site["name"]] = sid
            siteid_nwstackid[sid] = site["network_policysetstack_id"]
            siteid_nwpolid[sid] = site["policy_set_id"]
            siteid_qosstackid[sid] = site["priority_policysetstack_id"]
            siteid_natstackid[sid] = site["nat_policysetstack_id"]
            siteid_secpolid[sid] = site["security_policyset_id"]

    else:
        print("ERR: Could not retrieve sites")
        cloudgenix.jd_detailed(resp)

    #
    # Policy Original v1
    #
    print("\tPolicy Sets v1 & Rules")
    resp = cgx_session.get.policysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            polname_polid[item["name"]] = item["id"]
            polid_polname[item["id"]] = item["name"]

            resp = cgx_session.get.policyrules(policyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items",None)
                polid_polruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Policy Set (Original) {}".format(item["name"]))
                cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Policy Sets (Original)")
        cloudgenix.jd_detailed(resp)


    #
    # Path Stacks
    #
    print("\tPath Stacks")
    resp = cgx_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwstackid_policysetlist[item["id"]] = item["policyset_ids"]
            nwstackname_nwstackid[item["name"]] = item["id"]
            nwstackid_nwstackname[item["id"]] = item["name"]

    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
        cloudgenix.jd_detailed(resp)


    #
    # QOS Stacks
    #
    print("\tQoS Stacks")
    resp = cgx_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qosstackid_policysetlist[item["id"]] = item["policyset_ids"]
            qosstackname_qosstackid[item["name"]] = item["id"]
            qosstackid_qosstackname[item["id"]] = item["name"]

    else:
        print("ERR: Could not retrieve QoS Policy Set Stacks")
        cloudgenix.jd_detailed(resp)


    #
    # NAT Stacks
    #
    print("\tNAT Stacks")
    resp = cgx_session.get.natpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natstackid_policysetlist[item["id"]] = item["policyset_ids"]
            natstackname_natstackid[item["name"]] = item["id"]
            natstackid_natstackname[item["id"]] = item["name"]

    else:
        print("ERR: Could not retrieve NAT Policy Set Stacks")
        cloudgenix.jd_detailed(resp)

    #
    # Performance Stacks
    #
    print("\tPerformance Policy Stacks")
    resp = cgx_session.get.perfmgmtpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            perfstackid_policysetlist[item["id"]] = item["policyset_ids"]
            perfstackname_perfstackid[item["name"]] = item["id"]
            perfstackid_perfstackname[item["id"]] = item["name"]

    else:
        print("ERR: Could not retrieve Performance Policy Set Stacks")
        cloudgenix.jd_detailed(resp)
        
    #
    # Security Stacks
    #
    print("\tSecurity Stacks")
    resp = cgx_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwstackid_policysetlist[item["id"]] = item["policyset_ids"]
            ngfwstackname_ngfwstackid[item["name"]] = item["id"]
            ngfwstackid_ngfwstackname[item["id"]] = item["name"]

    else:
        print("ERR: Could not retrieve Security Policy Set Stacks")
        cloudgenix.jd_detailed(resp)

    #
    # Security Policy Sets
    #
    print("\Security Policy Sets & Rules")
    resp = cgx_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwpolname_ngfwpolid[item["name"]] = item["id"]
            ngfwpolid_ngfwpolname[item["id"]] = item["name"]

            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                ngfwpolid_ngfwruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Security Policy Set {}".format(item["name"]))

    else:
        print("ERR: Could not retrieve Security Policy Sets")
        cloudgenix.jd_detailed(resp)

    #
    # Original Security Pol Sets
    #
    print("\tOriginal Security Policy Sets & Rules")

    resp = cgx_session.get.securitypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            secpolname_secpolid[item["name"]] = item["id"]
            secpolid_secpolname[item["id"]] = item["name"]

            resp = cgx_session.get.securitypolicyrules(securitypolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                secpolid_secruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Original Security Policy Set {}".format(item["name"]))
                cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Original Security Policy Sets")
        cloudgenix.jd_detailed(resp)


    #
    # Network Policy Sets
    #
    print("\tPath Policy Sets & Rules")
    resp = cgx_session.get.networkpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwpolname_nwpolid[item["name"]] = item["id"]
            nwpolid_nwpolname[item["id"]] = item["name"]

            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                nwpolid_nwruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Network Policy Set {}".format(item["name"]))

    else:
        print("ERR: Could not retrieve Network Policy Sets")
        cloudgenix.jd_detailed(resp)


    #
    # QoS Policy Sets
    #
    print("\tQoS Policy Sets & Rules")

    resp = cgx_session.get.prioritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qospolname_qospolid[item["name"]] = item["id"]
            qospolid_qospolname[item["id"]] = item["name"]

            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                qospolid_qosruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for QoS Policy Set {}".format(item["name"]))

    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        cloudgenix.jd_detailed(resp)


    #
    # NAT Policy Sets
    #
    print("\tNAT Policy Sets & Rules")

    resp = cgx_session.get.natpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpolname_natpolid[item["name"]] = item["id"]
            natpolid_natpolname[item["id"]] = item["name"]

            resp = cgx_session.get.natpolicyrules(natpolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                natpolid_natruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for NAT Policy Set {}".format(item["name"]))

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        cloudgenix.jd_detailed(resp)

    #
    # Performance Policy Sets
    #
    print("\tPerformance Policy Sets & Rules")

    resp = cgx_session.get.perfmgmtpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            perfpolname_perfpolid[item["name"]] = item["id"]
            perfpolid_perfpolname[item["id"]] = item["name"]

            resp = cgx_session.get.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                perfpolid_perfruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Performance Policy Set {}".format(item["name"]))

    else:
        print("ERR: Could not retrieve Performance Policy Sets")
        cloudgenix.jd_detailed(resp)


    return appidlist



def getsites(policy_id, policy_type):
    sites = []
    if policy_type == "security":
        for sid in siteid_secpolid.keys():
            if siteid_secpolid[sid] == policy_id:
                sites.append(siteid_sitename[sid])
    
    elif policy_type == "ngfwstack":
        for sid in siteid_ngfwstackid.keys():
            if siteid_ngfwstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "perfstack":
        for sid in siteid_perfstackid.keys():
            if siteid_perfstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])
                
    elif policy_type == "nwstack":
        for sid in siteid_nwstackid.keys():
            if siteid_nwstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "qosstack":
        for sid in siteid_qosstackid.keys():
            if siteid_qosstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "natstack":
        for sid in siteid_natstackid.keys():
            if siteid_natstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "original":
        for sid in siteid_nwpolid.keys():
            if siteid_nwpolid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    return sites


def clean_exit(cgx_session):
    cgx_session.get.logout()
    sys.exit()


def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")


    # Commandline for entering Site info
    site_group = parser.add_argument_group('App Specific Information',
                                           'Information shared here will be used to get details about the policy sets & its associated sites')
    site_group.add_argument("--appname", "-A", help="Name of the App or use the special keyword ALL_APPS", default=None)
    site_group.add_argument("--datatype", "-DT", help="Get data for policies bound to sites or all policies. Pick from: ALL, BOUND", default=BOUND)


    args = vars(parser.parse_args())

    ############################################################################
    # Parse Args
    ############################################################################
    appname = args["appname"]
    datatype = args["datatype"]

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = prisma_sase.API(controller=args["controller"])
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    if PRISMASDWAN_CLIENT_ID and PRISMASDWAN_CLIENT_SECRET and PRISMASDWAN_TSG_ID:
        cgx_session.interactive.login_secret(client_id=PRISMASDWAN_CLIENT_ID, client_secret=PRISMASDWAN_CLIENT_SECRET, tsg_id=PRISMASDWAN_TSG_ID)
        if cgx_session.tenant_id is None:
            print("ERR: Service Account login failure. Please provide a valid Service Account.")
            sys.exit()

    else:
        print("ERR: No credentials provided. Please provide valid credentials in the prismasdwan_settings.py file. Exiting.")
        sys.exit()

    ############################################################################
    # Create Translation Dicts
    ############################################################################
    appidlist = create_dicts(cgx_session,appname)

    ############################################################################
    # Get App Usage
    ############################################################################

    appdata = pd.DataFrame()

    for appid in appidlist:

        appname = appid_appname[appid]
        print("Processing data for app {}".format(appname))

        #
        # Search Original Security Profiles
        #

        if datatype == ALL:
            attached_security_polids = set(secpolid_secpolname.keys())
        else:
            attached_security_polids = set(siteid_secpolid.values())

        attached_security_polids.discard(None)
        if len(attached_security_polids) > 0:

            for polid in attached_security_polids:
                polname = secpolid_secpolname[polid]

                sites = getsites(polid,SECURITY_POL)

                rules = secpolid_secruleslist[polid]

                for rule in rules:
                    appids = rule.get("application_ids", None)

                    if appids is None:
                        appdata = appdata.append({"app_name":appname,
                                                  "policy_type": "security",
                                                  "stack_name": "-",
                                                  "policy_name": polname,
                                                  "policy_rule": rule["name"],
                                                  "reference_type": "catchall - None",
                                                  "sites": sites,
                                                  "num_sites": len(sites)}, ignore_index=True)

                    if appids is not None:
                        if appids == ["any"]:
                            appdata = appdata.append({"app_name":appname,
                                                      "policy_type": "security",
                                                      "stack_name": "-",
                                                      "policy_name": polname,
                                                      "policy_rule": rule["name"],
                                                      "reference_type": "catchall - any",
                                                      "sites": sites,
                                                      "num_sites": len(sites)}, ignore_index=True)

                        elif appid in appids:
                            appdata = appdata.append({"app_name":appname,
                                                      "policy_type": "security",
                                                      "stack_name": "-",
                                                      "policy_name": polname,
                                                      "policy_rule": rule["name"],
                                                      "reference_type": "explicit - appid",
                                                      "sites": sites,
                                                      "num_sites": len(sites)}, ignore_index=True)


        #
        # Search NGFW STACK
        #
        if datatype == ALL:
            attached_ngfw_stackids = set(ngfwstackid_ngfwstackname.keys())
        else:
            attached_ngfw_stackids = set(siteid_ngfwstackid.values())

        attached_ngfw_stackids.discard(None)
        if len(attached_ngfw_stackids)>0:
            for stackid in attached_ngfw_stackids:
                stackname = ngfwstackid_ngfwstackname[stackid]
                sites = getsites(stackid,NGFW_STACK)

                policysets = ngfwstackid_policysetlist[stackid]

                for polid in policysets:
                    polname = ngfwpolid_ngfwpolname[polid]
                    rules = ngfwpolid_ngfwruleslist[polid]
                    if rules:
                        for rule in rules:
                            appids = rule.get("app_def_ids", None)

                            if appids is not None:
                                if appid in appids:
                                    appdata = appdata.append({"app_name":appname,
                                                              "policy_type": "network",
                                                              "stack_name": stackname,
                                                              "policy_name": polname,
                                                              "policy_rule": rule["name"],
                                                              "reference_type": "specific - appid",
                                                              "sites": sites,
                                                              "num_sites": len(sites)}, ignore_index=True)

        #
        # Search Performance Stack
        #
        if datatype == ALL:
            attached_perf_stackids = set(perfstackid_perfstackname.keys())
        else:
            attached_perf_stackids = set(siteid_perfstackid.values())

        attached_perf_stackids.discard(None)
        if len(attached_perf_stackids)>0:
            for stackid in attached_perf_stackids:
                stackname = perfstackid_perfstackname[stackid]
                sites = getsites(stackid,PERF_STACK)

                policysets = perfstackid_policysetlist[stackid]

                for polid in policysets:
                    polname = perfpolid_ngfwpolname[polid]
                    rules = perfpolid_perfruleslist[polid]
                    if rules:
                        for rule in rules:
                            appids = rule.get("app_def_ids", None)

                            if appids is not None:
                                if appid in appids:
                                    appdata = appdata.append({"app_name":appname,
                                                              "policy_type": "network",
                                                              "stack_name": stackname,
                                                              "policy_name": polname,
                                                              "policy_rule": rule["name"],
                                                              "reference_type": "specific - appid",
                                                              "sites": sites,
                                                              "num_sites": len(sites)}, ignore_index=True)
                                    
        #
        # Search NW STACK
        #
        if datatype == ALL:
            attached_nw_stackids = set(nwstackid_nwstackname.keys())
        else:
            attached_nw_stackids = set(siteid_nwstackid.values())

        attached_nw_stackids.discard(None)
        if len(attached_nw_stackids)>0:
            for stackid in attached_nw_stackids:
                stackname = nwstackid_nwstackname[stackid]
                sites = getsites(stackid,NW_STACK)

                policysets = nwstackid_policysetlist[stackid]

                for polid in policysets:
                    polname = nwpolid_nwpolname[polid]
                    rules = nwpolid_nwruleslist[polid]
                    if rules:
                        for rule in rules:
                            appids = rule.get("app_def_ids", None)

                            if appids is not None:
                                if appid in appids:
                                    appdata = appdata.append({"app_name":appname,
                                                              "policy_type": "network",
                                                              "stack_name": stackname,
                                                              "policy_name": polname,
                                                              "policy_rule": rule["name"],
                                                              "reference_type": "specific - appid",
                                                              "sites": sites,
                                                              "num_sites": len(sites)}, ignore_index=True)


        #
        # Search QoS STACK
        #
        if datatype == ALL:
            attached_qos_stackids = set(qosstackid_qosstackname.keys())
        else:
            attached_qos_stackids = set(siteid_qosstackid.values())

        attached_qos_stackids.discard(None)
        if len(attached_qos_stackids) > 0:
            for stackid in attached_qos_stackids:
                stackname = qosstackid_qosstackname[stackid]
                sites = getsites(stackid, QOS_STACK)

                policysets = qosstackid_policysetlist[stackid]
                for polid in policysets:
                    polname = qospolid_qospolname[polid]
                    rules = qospolid_qosruleslist[polid]
                    if rules:
                        for rule in rules:
                            appids = rule.get("app_def_ids", None)

                            if appids is not None:
                                if appid in appids:
                                    appdata = appdata.append({"app_name":appname,
                                                              "policy_type": "qos",
                                                              "stack_name": stackname,
                                                              "policy_name": polname,
                                                              "policy_rule": rule["name"],
                                                              "reference_type": "specific - appid",
                                                              "sites": sites,
                                                              "num_sites": len(sites)}, ignore_index=True)


        #
        # Search NAT STACK
        #
        if datatype == ALL:
            attached_nat_stackids = set(natstackid_natstackname.keys())
        else:
            attached_nat_stackids = set(siteid_natstackid.values())

        attached_nat_stackids.discard(None)
        if len(attached_nat_stackids) > 0:
            for stackid in attached_nat_stackids:
                stackname = natstackid_natstackname[stackid]
                sites = getsites(stackid, NAT_STACK)

                policysets = natstackid_policysetlist[stackid]
                for polid in policysets:
                    polname = natpolid_natpolname[polid]
                    rules = natpolid_natruleslist[polid]
                    if rules:
                        for rule in rules:
                            appids = rule.get("app_def_ids", None)

                            if appids is not None:
                                if appid in appids:
                                    appdata = appdata.append({"app_name": appname,
                                                              "policy_type": "nat",
                                                              "stack_name": stackname,
                                                              "policy_name": polname,
                                                              "policy_rule": rule["name"],
                                                              "reference_type": "specific - appid",
                                                              "sites": sites,
                                                              "num_sites": len(sites)},
                                                             ignore_index=True)


        #
        # Search Original Policy Sets (Policy v1)
        #
        if datatype == ALL:
            attached_polids = set(polid_polname.keys())
        else:
            attached_polids = set(siteid_nwpolid.values())

        attached_polids.discard(None)
        if len(attached_polids) > 0:
            for polid in attached_polids:
                polname = polid_polname[polid]

                sites = getsites(polid, ORIGINAL)
                rules = polid_polruleslist[polid]
                for rule in rules:
                    appids = rule.get("app_def_id", None)

                    if appids is not None:
                        if appid in appids:
                            appdata = appdata.append({"app_name": appname,
                                                      "policy_type": "nw_original",
                                                      "stack_name": "-",
                                                      "policy_name": polname,
                                                      "policy_rule": rule["name"],
                                                      "reference_type": "specific - appid",
                                                      "sites": sites,
                                                      "num_sites": len(sites)}, ignore_index=True)

    ############################################################################
    # Save Data to CSV
    ############################################################################
    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filename
    csvfile = os.path.join('./', '%s_appusage_%s.csv' % (tenant_str, curtime_str))
    print("Writing data to file {}".format(csvfile))
    appdata.to_csv(csvfile, index=False)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("INFO: Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()
