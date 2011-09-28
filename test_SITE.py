#!/usr/bin/env python

import sys
import commands 
import string

import datetime
import logging
import logging.handlers

from optparse import OptionParser
from random import choice

def print_error(ret, exit=False, msg=""):
    if ret[0] != 0:
        if not msg:
            msg = ret[1]
        logging.error("Check the following information:")
        logging.error(msg)
        if exit:
            sys.exit(ret[0])


def check_ces(bdii, vo):
    logging.info("Checking Computing Elements")
    logging.info("\tQuerying the BDII for the CEs")
    
    cmd = "lcg-info --list-ce --bdii %(bdii)s --sed --vo %(vo)s" % locals()
    logging.debug("Executing '%s'" % cmd)
    ret = commands.getstatusoutput(cmd)
    print_error(ret, exit=True)
    
    ces = ret[-1].splitlines()
    
    logging.info("\t\tFound: " + ",\n\t\t\t".join(ces))

    checked = []
    for ce in ces:
        if ce in checked:
            continue
    
        rets = []
        checked.append(ce)
    
        ce_host = ce.split(":")[0]

        logging.info("\tChecking %s" % ce_host)
    
        # Check the GridFTP
        cmd = "uberftp %s ls" % ce_host
        logging.debug("Executing '%s'" % cmd)
        ret = commands.getstatusoutput(cmd)
        if ret[0] != 0:
            print_error(ret)
        else:
            logging.info("\t\tGridFTP OK")
    
        aux, queue = ce.split("/",1)
        if "8443" in ce:
    
            logging.info("\t\tchecking glite-ce-allowed-submission")
            ret = commands.getstatusoutput("glite-ce-allowed-submission -n %s" % aux)
            print_error(ret)
            rets.append(ret)
    
            logging.info("\t\tchecking glite-ce-job-submit")
            ret = commands.getstatusoutput("glite-ce-job-submit -n -a -r %s test_submission.jdl" % ce)
            print_error(ret)
            rets.append(ret)
            if ret[0] == 0:
                url = ret[1].splitlines()[-1]
            else:
                continue
            logging.info("\t\t\tJob ID: %s" % url)
            while True:
                ret = commands.getstatusoutput("glite-ce-job-status -n %s" % url)
                if "[DONE-OK]" in ret[1]:
                    logging.info("\t\tsubmission ok, check the following job id for further details %s" % url)
                    break
                elif "[DONE-FAILED]" in ret[1]:
                    ret = (1, ret[1] )
                    print_error(ret)
                    break
            print_error(ret)
            rets.append(ret)
    
        else:
            # I will not waste much effort on this, since lcg-CE are condemned to disappear.
            logging.info("\t\tchecking globus-job-run to ce")
            cmd = "globus-job-run %s /bin/hostname" % aux
            logging.debug("Executing '%s'" % cmd)
            ret = commands.getstatusoutput(cmd) 
            print_error(ret)
            rets.append(ret)
    
            logging.info("\t\tchecking globus-job-run to fork")
            cmd = "globus-job-run %s/jobmanager-fork /bin/pwd" % aux
            logging.debug("Executing '%s'" % cmd)
            ret = commands.getstatusoutput(cmd) 
            print_error(ret)
            rets.append(ret)
    
            logging.info("\t\tchecking globus-job-run to queue")
            queue = queue.split("-")
            cmd = "globus-job-run %s/%s-%s -queue %s /bin/pwd" % tuple([aux] + queue)
            logging.debug("Executing '%s'" % cmd)
            ret = commands.getstatusoutput(cmd) 
            print_error(ret)
            rets.append(ret)
    
        if not any([i[0] for i in rets]):
            logging.info("\t\tJob submission seems OK")
        else:
            logging.critical("\t\tJob submission has problems, check above errors")


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
    logging.info("Checking Storage Elements")
    logging.info("\tQuerying the BDII for the SEs")

    logging.debug("Executing '%s'" % cmd)
    ret = commands.getstatusoutput("lcg-info --list-se --bdii %(bdii)s --sed --vo VO:%(vo)s" % locals())
    print_error(ret, exit=True)

    ses = ret[-1].splitlines()
    logging.info("\t\tFound: " + ",\n\t\t\t".join(ses))

    checked = ["gridce05.ifca.es"]
    for se in ses:
        if se in checked:
            continue

        rets = []
        checked.append(se)
        
        logging.info("\tChecking %s" % se)
        cmd = "uberftp %s ls" % se
        logging.debug("Executing '%s'" % cmd)
        ret = commands.getstatusoutput(cmd)
        if ret[0] != 0:
            print_error(ret)
        else:
            logging.info("\t\tGridFTP is up")
        rets.append(ret)


        cmd = "ldapsearch -x -LLL -H ldap://%(bdii)s -b o=grid '(&(objectClass=GlueSATop) (GlueVOInfoAccessControlBaseRule=VO:%(vo)s) (GlueChunkKey=GlueSEUniqueID=%(se)s))' GlueVOInfoPath" % locals()
        logging.debug("Executing '%s'" % cmd)
        ret = commands.getstatusoutput(cmd)
        print_error(ret)
        rets.append(ret)

        se_paths = filter_and_join_ldap(ret[1], "GlueVOInfoPath")

        cmd = "ldapsearch -x -LLL -H ldap://%(bdii)s -b o=grid '(&(objectClass=GlueSEControlProtocol) (GlueChunkKey=GlueSEUniqueID=%(se)s) (GlueSEControlProtocolType=SRM) (GlueSEControlProtocolVersion=2.2.0))' GlueSEControlProtocolEndpoint" % locals()
        logging.debug("Executing '%s'" % cmd)
        ret = commands.getstatusoutput(cmd)
        print_error(ret)
        rets.append(ret)

        endpoints = [i.replace("httpg","srm") for i in filter_and_join_ldap(ret[1], "GlueSEControlProtocolEndpoint")]

#        ret = commands.getstatusoutput("lcg-cp -v --vo %(vo)s file:/etc/issue srm://%(se)s/%(se_path)s/%(randfile)s" % locals()) 
        for endpoint in endpoints:
            for se_path in se_paths:
                logging.info("\t\tUploading file to %(endpoint)s/%(se_path)s" % locals())
                randfile = ''.join([choice(string.letters + string.digits) for i in range(15)])
                cmd = "lcg-cp -v -b --vo %(vo)s -D srmv2 file:/etc/issue %(endpoint)s/\?SFN=%(se_path)s/%(randfile)s" % locals()
                logging.debug("Executing '%s'" % cmd)
                ret = commands.getstatusoutput(cmd)
                print_error(ret)
                rets.append(ret)

                if ret[0] == 0:
                    logging.info("\t\tRemoving uploaded file")
                    cmd = "lcg-del -l -v -b --vo %(vo)s -D srmv2 %(endpoint)s/\?SFN=%(se_path)s/%(randfile)s" % locals()
                    logging.debug("Executing '%s'" % cmd)
                    ret = commands.getstatusoutput(cmd)
                    print_error(ret)
                    rets.append(ret)

        if not any([i[0] for i in rets]):
            logging.info("\t\tData management seems OK")
        else:
            logging.critical("\t\tData management has problems, check above errors")



def check_bdii(bdii):
    logging.info("Checking BDII information (TBD)")


def get_proxy():
    # Check for proxy validity
    ret = commands.getstatusoutput("voms-proxy-info -exists")
    print_error(ret, exit=True, msg="VOMS: No valid proxy found!")

    ret = commands.getstatusoutput("voms-proxy-info -vo")
    print_error(ret, exit=True)

    vo = ret[1]
    return vo


def set_logging(level=logging.INFO):

    outfile = "%s.log" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S.%f")

    logging.basicConfig(level=logging.DEBUG,
            format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
            datefmt="%m-%d %H:%M",
            filename=outfile,
            filemode="w")

    console = logging.StreamHandler()
    console.setLevel(level)
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    logging.info("Detailed output for this run will be written to '%s'" % outfile)

set_logging()

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

    vo = get_proxy()

    logging.info("Checking with VO '%s'" % vo)

    bdii = args[-1]
    check_bdii(bdii)

    if all or opts.onlyce:
       check_ces(bdii, vo)
    if all or opts.onlyse:
       check_ses(bdii, vo)

if __name__ == "__main__":
    main()
sys.exit(0)
