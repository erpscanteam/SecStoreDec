#!/usr/bin/env python

import argparse
import os.path
import jks
import re

help_desc = '''
This program decrypts SecStore.key and SecStore.properties files, encrypted data from "J2EE_CONFIGENTRY" table.
(c) ERPScan 2018
'''

SECKEY_REGEXP = "(\d.\d{2}\.\d{3})\.\d{3}\|(.*)"


# guess the SID using the fact that property names are formatted
# like this: 'foo/bar/SID = xxxxx'
def get_sid_from_prop(prop):
    propnames = [l.split('=')[0] for l in open(prop, 'r') if not
    '$internal' in l and not l.startswith('#')]
    sid_candidates = [p.split('/')[-1] for p in propnames]
    try:
        sid = filter(lambda e: re.match('^\w{3}$', e), sid_candidates)[0]
    except:
        print "SID not properly matched! Our candidates where %s", sid_candidates
        exit(-1)
    return sid


# multi-byte key XOR
def xor(data, key):
    l = len(key)
    return bytearray((
        (ord(data[i]) ^ key[i % l]) for i in range(0, len(data))
    ))


# un-XOR the key from SecStore.key with static secret
def deobfuscate_seckey(secfkey):
    keyfile = open(secfkey, 'r').read()
    try:
        fullver, key_obfuscated = re.search(SECKEY_REGEXP, keyfile).groups()
    except:
        print "Your key file %s seems broken." % secfkey
        exit(-1)
    ver = True if fullver == '7.00.000' else False
    secret = [0x2b, 0xb6, 0x8f, 0xfa, 0x96, 0xec, 0xb6, 0x10, \
              0x24, 0x47, 0x92, 0x65, 0x17, 0xb0, 0x9, 0xc4, \
              0x3e, 0xa, 0xd7, 0xbd]
    key_cleared = xor(key_obfuscated, secret)
    return str(key_cleared), ver


# Decrypt SecStore.properties with KeyPhrase from SecStore.key
def decprop(secfprop, keyphrase):
    ciphertext = [l for l in open(secfprop, 'r') if not '$internal' in l]
    salt = 16 * b'\x00'
    itr = 0
    plaintextfin = {}
    for i in ciphertext:
        m = re.search("(.*?)=(.*)", i)
        if m:
            prop, value = m.groups()
            value = value.replace("\\r\\n", "")
            value_raw = value.decode('base64')
            jks_obj = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(value_raw, keyphrase, salt, itr).split('|')
            prop_dec_value = jks_obj[2][:int(jks_obj[1])]
            plaintextfin[prop] = prop_dec_value
    if plaintextfin == {}:
        print "Format unexpected for properties file %s" % secfprop
        exit(-1)
    return plaintextfin


# Check that SecStore files exist
def check_files(pathkey, pathprop):
    if (os.path.isfile(pathkey) != True or os.path.isfile(pathprop) != True):
        print "Can not find %s or %s" % (pathkey, pathprop)
        exit()


def auto(pathprop, pathkey):
    key, ver_recent = deobfuscate_seckey(pathkey)  # Decrypt KeyPhrase
    print "Keyphrase:", key
    if ver_recent:  # Decrypt SecStore.properties
        for k, v in decprop(pathprop, key).iteritems():
            print "%s = %s" % (k, v)
    else:  # SID is necessary only for version < 7.00.000
        sid = get_sid_from_prop(pathprop)
        try:
            for k, v in decprop(pathprop, key + sid).iteritems():
                print "%s = %s" % (k, v)
        except:
            print 'Wrong SID, can not decrypt %s' % pathprop


def decrypt_handler(prop, key):
    check_files(prop, key)
    auto(prop, key)


# data_ciph = '[00|01] XX enc_msg'
def decrypt_DES(data_ciph, keyphrase, salt, itr):
    alphabet_skip = 18
    try:
        data_ciph = data_ciph.decode('hex')
    except TypeError as e:
        print e.message
        exit(-3)
    enc_fmt, enc_msg = data_ciph[0], data_ciph[2:]
    if enc_fmt == '\x00':
        return enc_msg.decode('base64')[alphabet_skip:]
    elif enc_fmt == '\x01':
        try:
            dec = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(enc_msg, keyphrase, salt, itr)[alphabet_skip:]
        except jks.util.BadPaddingException:
            print "Bad padding, you're encrypted data is probably corrupted or key is wrong"
            exit(-2)
        except jks.util.BadDataLengthException:
            print "Wrong data length"
            exit(-3)
        return dec
    else:
        return "Format of data not understood (should begin with 0x00 or 0x01)"


def dec_data(data, key):
    salt = 16 * b'\x00'
    itr = 0
    return decrypt_DES(data, key, salt, itr)


# Main function
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(help="select object for decryption", dest='cmd')

    parser_secStore = subparsers.add_parser('dss', help="decrypt secstore files")
    parser_secStore.add_argument('secfiles', metavar='arguments', nargs='*',
                                 default=["SecStore.properties", "SecStore.key"],
                                 help='Custom path to SecStore.properties and SecStore.key (by default open files in working directory)')

    parser_Data = subparsers.add_parser('dd', help="decrypt data from J2EE_CONFIGENTRY table")

    parser_Data.add_argument('-k', '--keyphrase', action="store", help='KeyPhrase to decrypt data', required=True)
    parser_Data.add_argument('-d', '--data', action="store", help='data for decryption in HEX format (ex: 01011c..)',
                             required=True)

    args = parser.parse_args()

    if args.cmd == 'dss':
        decrypt_handler(args.secfiles[0], args.secfiles[1])
    if args.cmd == 'dd':
        print dec_data(args.data, args.keyphrase)
