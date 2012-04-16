EGI cert tool
=============

Small tool to make the certification process of a new site less
tedious. This tool will run several tests by itself, namely:

1. Checks the BDII for correct information (to be done).
2. Query the BDII for the published CEs.
3. Computing Element tests:

   a) For the lcg-CE:

      - GridFTP is running.
      - globus-job-run directly to the CE.
      - globus-job-run to the fork JM.
      - globus-job-run to the queue.

   b) For the CREAM-CE:

      - GridFTP is running.
      - glite-ce-allowed-submission.
      - glite-ce-job-submit.

4. Storage Element tests:

   - GridFTP is running.
   - Can upload and delete a file (using lcg-utils).

Instructions
------------

Execute::

 ./run_tests.py --help
 
for more details on usage.

NOTICE
======

This is not any official tool. It is only a tool to help me with
the preliminary certification tests to join our NGI (NGI_IBERGRID).
Use it at your own risk.

Questions, bugs, suggestions
============================
Just drop me a line or open an issue on github.

:Email: aloga <at> ifca.unican.es
:Homepage: https://devel.ifca.es/~aloga/
:On github: https://github.com/alvarolopez/egi-certool/

