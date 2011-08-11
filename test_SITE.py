#!/usr/bin/env python

import sys
import commands 
import string

from optparse import OptionParser
from random import choice

def print_error(ret, exit=False):
    if ret[0] != 0:
        print >> sys.stderr, "-" * 80
        print >> sys.stderr, "Error: Check the following information"
        print >> sys.stderr, ret[1]
        print >> sys.stderr, "-" * 80
        if exit:
            sys.exit(ret[0])


def check_ces(bdii, vo):
    print
    print "#" * 80
    print "Checking Computing Elements"
    print "\tQuerying the BDII for the CEs"
    
    ret = commands.getstatusoutput("lcg-info --list-ce --bdii %(bdii)s --sed --vo %(vo)s" % locals())
    print_error(ret, exit=True)
    
    ces = ret[-1].splitlines()
    
    print "\t\tFound: " + ",\n\t\t\t".join(ces)

    checked = []
    for ce in ces:
        if ce in checked:
            continue
    
        rets = []
        checked.append(ce)
    
        ce_host = ce.split(":")[0]

        print "\tChecking %s" % ce_host
    
        ret = commands.getstatusoutput("uberftp %s ls" % ce_host)
        if ret[0] != 0:
            print_error(ret)
        else:
            print "\t\tGridFTP OK"
    
        aux, queue = ce.split("/",1)
        if "8443" in ce:
    
            print "\t\tchecking glite-ce-allowed-submission"
            ret = commands.getstatusoutput("glite-ce-allowed-submission -n %s" % aux)
            print_error(ret)
            rets.append(ret)
    
            print "\t\tchecking glite-ce-job-submit"
            ret = commands.getstatusoutput("glite-ce-job-submit -n -a -r %s test_submission.jdl" % ce)
            print_error(ret)
            rets.append(ret)
            if ret[0] == 0:
                url = ret[1].splitlines()[-1]
            else:
                continue
            print "\t\t\tJob ID: %s" % url
            while True:
                ret = commands.getstatusoutput("glite-ce-job-status -n %s" % url)
                if "[DONE-OK]" in ret[1]:
                    print "\t\tsubmission ok, check the following job id for further details %s" %url
                    break
                elif "[DONE-FAILED]" in ret[1]:
                    ret = (1, ret[1] )
                    print_error(ret)
                    break
            print_error(ret)
            rets.append(ret)
    
        else:
            # I will not waste much effort on this, since lcg-CE are condemned to disappear.
            print "\t\tchecking globus-job-run to ce"
            ret = commands.getstatusoutput("globus-job-run %s /bin/hostname" % aux) 
            print_error(ret)
            rets.append(ret)
    
            print "\t\tchecking globus-job-run to fork"
            ret = commands.getstatusoutput("globus-job-run %s/jobmanager-fork /bin/pwd" % aux) 
            print_error(ret)
            rets.append(ret)
    
            print "\t\tchecking globus-job-run to queue"
            queue = queue.split("-")
            ret = commands.getstatusoutput("globus-job-run %s/%s-%s -queue %s /bin/pwd" % tuple([aux] + queue)) 
            print_error(ret)
            rets.append(ret)
    
        if not any([i[0] for i in rets]):
            print "\t\tJob submission seems OK"
        else:
            print "\t\tJob submission has problems, check above errors"


def filter_and_join_ldap(data, query):
    """Filter results to only those of query and join line breaks from ldapsearch."""
    got = False
    aux = []
    for i in data.splitlines():
        if i.startswith(query):
            got = True
            aux.append([i.split(":",1)[-1].strip()])
        elif i.startswith(" ") and got:
            aux[-1].append(i.strip())
        elif got:
            got = False
    return ["".join(i) for i in aux]


def check_ses(bdii, vo):
    print
    print "#" * 80
    print "Checking Storage Elements"
    print "\tQuerying the BDII for the SEs"

    ret = commands.getstatusoutput("lcg-info --list-se --bdii %(bdii)s --sed --vo VO:%(vo)s" % locals())
    print_error(ret, exit=True)

    ses = ret[-1].splitlines()
    print "\t\tFound: " + ",\n\t\t\t".join(ses)

    checked = ["gridce05.ifca.es"]
    for se in ses:
        if se in checked:
            continue

        rets = []
        checked.append(se)
        
        print "\tChecking %s" % se
        ret = commands.getstatusoutput("uberftp %s ls" % se)
        if ret[0] != 0:
            print_error(ret)
        else:
            print "\t\tGridFTP is up"
        rets.append(ret)


        ret = commands.getstatusoutput("ldapsearch -x -LLL -H ldap://%(bdii)s -b o=grid '(&(objectClass=GlueSATop) (GlueVOInfoAccessControlBaseRule=VO:%(vo)s) (GlueChunkKey=GlueSEUniqueID=%(se)s))' GlueVOInfoPath" % locals())
        print_error(ret)
        rets.append(ret)

        se_paths = filter_and_join_ldap(ret[1], "GlueVOInfoPath")

        ret = commands.getstatusoutput("ldapsearch -x -LLL -H ldap://%(bdii)s -b o=grid '(&(objectClass=GlueSEControlProtocol) (GlueChunkKey=GlueSEUniqueID=%(se)s) (GlueSEControlProtocolType=SRM) (GlueSEControlProtocolVersion=2.2.0))' GlueSEControlProtocolEndpoint" % locals())
        print_error(ret)
        rets.append(ret)

        endpoints = [i.replace("httpg","srm") for i in filter_and_join_ldap(ret[1], "GlueSEControlProtocolEndpoint")]

#        ret = commands.getstatusoutput("lcg-cp -v --vo %(vo)s file:/etc/issue srm://%(se)s/%(se_path)s/%(randfile)s" % locals()) 
        for endpoint in endpoints:
            for se_path in se_paths:
                print "\t\tUploading file to %(endpoint)s/%(se_path)s" % locals()
                randfile = ''.join([choice(string.letters + string.digits) for i in range(15)])
                ret = commands.getstatusoutput("lcg-cp -v -b --vo %(vo)s -D srmv2 file:/etc/issue %(endpoint)s/\?SFN=%(se_path)s/%(randfile)s" % locals())
                print_error(ret)
                rets.append(ret)

                if ret[0] == 0:
                    print "\t\tRemoving uploaded file"
                    ret = commands.getstatusoutput("lcg-del -l -v -b --vo %(vo)s -D srmv2 %(endpoint)s/\?SFN=%(se_path)s/%(randfile)s" % locals())
                    print_error(ret)
                    rets.append(ret)

        if not any([i[0] for i in rets]):
            print "\t\tData management seems OK"
        else:
            print "\t\tData management has problems, check above errors"



def check_bdii(bdii):
    print "Checking BDII information (TBD)..."

def main():
    usage = """%prog [options] <siteBDII host>:<port>"""
    parser = OptionParser(usage=usage)
#    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
#            default="False", help="Print verbose results")
    parser.add_option("-c", "--ces", dest="onlyce", action="store_true",
            default=False, help="Check only Computing Elements")
    parser.add_option("-s", "--ses", dest="onlyse", action="store_true",
            default=False, help="Check only Storage Elements")

    (opts, args) = parser.parse_args()

    if opts.onlyse and opts.onlyce:
        parser.error("-s and -c options are mutually exclusive")
    elif opts.onlyse or opts.onlyse:
        all = False
    else:
        all = True

    if len(args) != 1:
        parser.error("Error, you have to specify one (and only one) siteBDII")

    ret = commands.getstatusoutput("voms-proxy-info --vo")
    print_error(ret, exit=True)

    vo = ret[1]

    bdii = args[-1]
    check_bdii(bdii)

    if all or opts.onlyce:
       check_ces(bdii, vo)
    if all or opts.onlyse:
       check_ses(bdii, vo)

if __name__ == "__main__":
    main()
sys.exit(0)
