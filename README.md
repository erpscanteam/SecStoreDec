# Requirements

You need `pyjks` package to use this script.

```
pip install pyjks
```

# Usage

This program decrypts SAP `SecStore.key` and `SecStore.properties`
files and encrypted data from the `J2EE_CONFIGENTRY` table.

`SecStoreDec.py` can work in two modes:
- `dss`: Decrypt SecStore (used to decypt `SecStore.properties` with
  `SecStore.key`)
- `dd`: Decrypt raw data

## SecStore decryption

If `SecStore.key` and `SecStore.properties` files are located in the
same directory you can omit them as arguments:

```
python SecStoreDec.py dss
```

else you can set any path you like:

```
python SecStoreDec.py dss ../SecStore.properties ../SecStore.key
```

## Raw data decryption

The second mode is used to decrypt encrypted data in
`J2EE_CONFIGENTRY`. You need the keyphrase and the encrypted data in
hex format. Example:

```
python SecStoreDec.py dd -k MYKEYPHRASE -d 01011c...
```

NB: The keyphrase is obtained via decryption of the
`SecStore.properties` file


Special thanks to [@gelim](https://twiter.com/gelim) and [@_chipik](https://twiter.com/_chipik)
