Malwarehouse is a warehouse for your malware. Malwarehouse is a useful command line utility for storing, tagging,  storing, and searching for malware. This is intended to help analyst manage their workflow by conducting basic triage and making it easy to look up past samples.

## Requirements
* Python 2.7

### Libraries
* [PyDeep](https://github.com/kbandla/pydeep)
* [sqlalchemy](http://www.sqlalchemy.org)
* [magic](https://github.com/ahupp/python-magic) & [libmagic](http://www.brambraakman.com/blog/comments/installing_libmagic_in_mac_os_x_for_python-magic/)
* poster

## Authors
* Scott J Roberts - [@sroberts](https://twitter.com/sroberts)
* Mina Naguib - [@warebot](https://twitter.com/warebot)

## Setup - Databases
For initial DB setup, run ```python setup_db.py```
Using sqlalchecmy, Malwarehouse can now support a wider variety of database engines. 

* You simply need to create the database and a user account with sufficient read/write privileges.
* Once created, setup the database section of the malwarehouse.cfg file accordingly.
  * **EXAMPLE:** postgresql://USER:PASSWORD@SERVER/DB

For more information, refer to http://docs.sqlalchemy.org/en/rel_0_8/core/engines.html#database-urls

## Usage

```
malware_manager.py [-h] [-r [RECENT]] [-s SOURCE] [-t TAGS] [-n NOTES]
                       [-f FIND] [-l LOAD] [-d DELETE]

-h 	displays help
-r 	search db for most recent n samples [default=5]
-f	search db for a sample either by md5 or sha256
-l 	load a new sample to the db for analysis
-s      add source text of the sample to the report
-n	add additional text notes to the report
```

### Plugins
Malwarehouse now allows you to seamlessly integrate your own plugins to automagically run during analysis. For now, please see the virus total plugin for reference.

## License
See LICENSE for more information

## Thanks
* Jonathan Hencinski
* Chris St.Myers
* @Xen0ph0n
