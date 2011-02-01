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
    
    print "\t\tFound: " + "\n\t\t\t".join(ces)

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


def check_ses(bdii, vo):
    print
    print "#" * 80
    print "Checking Storage Elements"
    print "\tQuerying the BDII for the SEs"

    ret = commands.getstatusoutput("lcg-info --list-se --bdii %(bdii)s --sed --vo %(vo)s" % locals())
    print_error(ret, exit=True)

    ses = ret[-1].splitlines()
    print "\t\tFound: " + "\n\t\t\t".join(ses)

    checked = []
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

        randfile = ''.join([choice(string.letters + string.digits) for i in range(15)])

        print "\t\tchecking copy and register"
        ret = commands.getstatusoutput("lcg-cr -v --vo %(vo)s -d %(se)s -l lfn:/grid/%(vo)s/%(randfile)s file:/etc/issue" % locals()) 
        print_error(ret)
        rets.append(ret)
        if ret[0] == 0:
            print "\t\tchecking removal of uploaded file"
            ret = commands.getstatusoutput("lcg-del -v --vo %(vo)s lfn:/grid/%(vo)s/%(randfile)s -a" % locals())
            print_error(ret)
            rets.append(ret)

        if not any([i[0] for i in rets]):
            print "\t\tData management seems OK"
        else:
            print "\t\tData management has problems, check above errors"



def check_bdii(bdii):
    print "Checking BDII information (TBD)..."

def main():
    parser = OptionParser()
#    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
#            default="False", help="Print verbose results")
    parser.add_option("-c", "--only-ces", dest="onlyce", action="store_true",
            default=False, help="Check onlt Computing Elements")
    parser.add_option("-s", "--only-ses", dest="onlyse", action="store_true",
            default=False, help="Check only Storage Elements")

    (opts, args) = parser.parse_args()

    if opts.onlyse and opts.onlyce:
        parser.error("-s and -c options are mutually exclusive")
    elif opts.onlyse or opts.onlyse:
        all = False
    else:
        all = True

    
    if len(sys.argv) != 2:
        print >> sys.stderr, "Usage %s <siteBDII>" % sys.argv[0]

    ret = commands.getstatusoutput("voms-proxy-info --vo")
    print_error(ret, exit=True)

    vo = ret[1]

    bdii = sys.argv[-1]
    check_bdii(bdii)

    if all or pts.onlyce:
       check_ces(bdii, vo)
    if all or opts.onlyse:
       check_ses(bdii, vo)

if __name__ == "__main__":
    main()
sys.exit(0)
