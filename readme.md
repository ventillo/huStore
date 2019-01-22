# Huawei OceanStor REST API CLI interface (python library)
The purpose of this library / CLI tool is to provide a simple API for objects on an OceanStor 6800 / 5500 V3.

## The "admin" method
If you supply (admin) user and pass in the id.pass file, keep in mind the permissions you want to set the file with, so it is not readable by everybody. Further user context tweaks are needed to abscure these credentials more, I leave that with you.

## Integrated help
```
$ ./huawei_rest.py -h
usage: huawei_rest.py [-h] [-i HOST [HOST ...]] [-u USER] [-p PASSWORD] [-A]
                      [-d [{system,pool,disk,host,perf} [{system,pool,disk,host,perf} ...]]]
                      [-f]

DESCRIPTION:
    Huawei OceanStor REST API troubleshooting and monitoring script


optional arguments:
  -h, --help            show this help message and exit
  -i HOST [HOST ...], --host HOST [HOST ...]
                        IP or FQDN of the Huawei storage box
  -u USER, --user USER  Username, obviously
  -p PASSWORD, --password PASSWORD
                        Optionally, the password may be supplied
  -A, --admin           Optionally, the password may be supplied by file id.pass
  -d [{system,pool,disk,host,perf} [{system,pool,disk,host,perf} ...]], --details [{system,pool,disk,host,perf} [{system,pool,disk,host,perf} ...]]
                        Information section. You can optionally select one or
                        more categories
  -f, --failed          Optionally, you might filter only failed components

ERROR CODES:
     1:

EXAMPLES:
```
