Requirements:
You need "pyjks" package to use this script.

`pip install pyjks`

This program decrypts SAP SecStore.key and SecStore.properties files, encrypted data from "J2EE_CONFIGENTRY" table.
SecStoreDec.py can work in 2 modes: *dss - Decrypt SecStore* and *dd - Decrypt Data*
The first mode you can use to decrypt SecStore.key and SecStore.properties files. Example:

If SecStore.key and SecStore.properties files are located in the same directory, then :
```
    python SecStoreDec.py dss
```
Else you can set any path you like:
```
    python SecStoreDec.py dss ../SecStore.properties ../SecStore.key
```
The second mode is used to decrypt encrypted data in J2EE_CONFIGENTRY. You need key-phrase and encrypted data in hex-format. Example:
```
    python SecStoreDec.py dd -k MYKEYPHRASE -d 01011c...
```
