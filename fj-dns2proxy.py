#!/usr/bin/python
# -*- coding:Utf-8 -*-

Hello_Word = "                                                       \n\
    ____  _   _ ____    ____  ____   _____  ____   __                \n\
   |  _ \| \ | / ___|  |  _ \|  _ \ / _ \ \/ /\ \ / /                \n\
   | | | |  \| \___ \  | |_) | |_) | | | \  /  \ V /                 \n\
   | |_| | |\  |___) | |  __/|  _ <| |_| /  \   | |                  \n\
   |____/|_| \_|____/  |_|   |_| \_|\___/_/\_\  |_|                  \n\
                                      V 1.0 - 11/2016                \n\
                                     Frederic JELMONI                \n\
                                  frederic@jelmoni.fr                \n\
-h for Usage.                                                        \n\
                                                                     \n\
"
# ------------------------------------------------------------------------------
import argparse
import socket
import sys
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, hexdump
import re


colR = '\033[1;31m' # Red
colg = '\033[0;32m' # Green
colG = '\033[1;32m' # Green
colY = '\033[1;33m' # Yellow
colB = '\033[1;34m' # Blue
colW = '\033[1;37m' # Write 
colD = '\033[0;39m' # Default

buf = 1024
a = 0   

tmp_string = ''
translated_string = {}      # list of queries rewrited. Used to translate answers
translate_regex = {}        # rules to translation decision

configs_path = os.path.dirname(os.path.realpath(__file__))
transform_file = "%s/fj-transform.cfg"    % configs_path


# ------------------------------------------------------------------------------
def process_conf_files():

    nsfile = open(transform_file, 'r')
    #for line in nsfile.readlines():
    for line in nsfile.readlines():
        #line = line.decode('raw_unicode_escape')
        if line.startswith('#'): # instead of line[0] - this way it never throws an exception in an empty line
            continue
        #line = re.sub('c', '00', line)
        line = line.rstrip()
        regex_pattern = line.split(':')[0]
        regex_replace = line.split(':')[1]
        translate_regex[regex_pattern] = regex_replace 

    nsfile.close()

    return 0


# ------------------------------------------------------------------------------
def process_request(msg):

    global tmp_string
    global translated_string

    msg_decoded = DNS(msg)
    #msg_decoded.show()

    # DNS question record
    msg_count = msg_decoded[DNS].qdcount
    for a in range(0, msg_count):
        qname = msg_decoded[DNS].qd[a].qname
        qtype = msg_decoded[DNS].qd[a].qtype
        qclass = msg_decoded[DNS].qd[a].qclass
        new_qname = qname

        # Test translation regexp 
        for regex_pattern in translate_regex.keys():

            # Test regexp
            new_qname = re.sub(regex_pattern, translate_regex[regex_pattern], qname)
            # if regex match
            if new_qname <> qname:
               break   # stop at the first match
        

        if new_qname <> qname:
            msg_decoded[DNS].qd[a].qname = new_qname
            # Add translation to dictionary
            translated_string[new_qname] = qname
            print colG + qname + colR + ' rewrite to: '+colG + new_qname + colD,  
        else:
            print colG + qname + colD,

        print '(%s %s)' % (qtype, qclass),


    tmp_string = str(msg_decoded)

    return 0

# ------------------------------------------------------------------------------
def process_answer(msg):

    global tmp_string
    global translated_string

    msg_decoded = DNS(msg)
    #msg_decoded.show()
    print '-->',
 
    # DNS question record
    msg_count = msg_decoded[DNS].qdcount
    for a in range(0, msg_count):
        qname = msg_decoded[DNS].qd[a].qname
        qtype = msg_decoded[DNS].qd[a].qtype
        qclass = msg_decoded[DNS].qd[a].qclass
   
        # reverse translation (if exist)
        try:
            ori_qname = translated_string[qname]
            msg_decoded[DNS].qd[a].qname = ori_qname
        except KeyError:
            pass

    # DNS Answer record
    msg_count = msg_decoded[DNS].ancount
    for a in range(0, msg_count):
        rrname = msg_decoded[DNS].an[a].rrname
        rdata = msg_decoded[DNS].an[a].rdata

        print colB + rdata + colD,

        # reverse translation (if exist)
        try:
            ori_rrname = translated_string[rrname]
            msg_decoded[DNS].an[a].rrname = ori_rrname
        except KeyError:
            pass

    #msg_decoded.show()
    tmp_string = str(msg_decoded)

    return 0

# ------------------------------------------------------------------------------
def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument("-i",   "--ipLocal", help="Local IP to bind (default:all)", default="")
    parser.add_argument("-r",   "--resolver",help="resolver DNS (default:8.8.8.8)", default="8.8.8.8")
    parser.add_argument("-c",   "--nocolor", help="Print without color", action="store_true")
    parser.add_argument("-s",   "--silence", help="Silence mode", action="store_true")

    args = parser.parse_args()

    return args


# ---------------------------------[ MAIN FUNCTION ]-------------------------------------
def run(ipLocal, resolver, nocolor, silence):
    global a
    global colR, colG, colg, colY, colB, colD, colW
    global translated_string


    add_local = (ipLocal, 53)
    add_resolver = (resolver, 53)

    print "---------------------"
    print 'Local address    :', add_local
    print 'Resolver address :', add_resolver
    print 'No color mode    :', nocolor
    print 'Silence mode     :', silence
    print "---------------------"

    if nocolor:
        colR = ''; colG = ''; colg = ''; colY = ''; colB = ''; colD = ''; colW = ''

    
    process_conf_files()
    #print translate_regex


    socket.setdefaulttimeout(1)
    socket_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    try:
        socket_in.bind(add_local)
    except:
        print colR + 'Error socket bind' + colD,
        print add_local
        exit(1)


    while True:
  
        # clear translate table 
        translated_string = {}

        # receive client query
        try:
            msg_client, add_client = socket_in.recvfrom(buf)

            a += 1
            print a,
 
            print 'Request from %s%s%s (%s):' % (colY, add_client[0], colD, len(msg_client)),

            process_request(msg_client)
            msg_client = tmp_string
            

           # send client query --to--> server
            try:
                #socket_out.sendto(msg_client, add_resolver)
                socket_out.sendto(msg_client, add_resolver)

                # receive server reponse
                try:
                    msg_server, adr = socket_out.recvfrom(buf)
                    process_answer(msg_server),
                    msg_server = tmp_string
                    
                    # send server reponse --to--> client 
                    try:
                        socket_in.sendto(msg_server, add_client)
                    except:
                        print colR + 'Error socket sendto client' + colD,
                        print msg_server, add_client 
                        break

                except socket.timeout:
                    print colR + 'Server Timeout !' + colD,
                    pass
                except:
                    print colR + 'Error socket recvfrom server' + colD,
                    print msg_client, add_resolver
                    break
   
            except:
                print colR + 'Error socket sendto server' + colD,
                print msg_client, add_resolver
                break

            print

        except socket.timeout:
            #print 'Client Timeout'
            pass
        except KeyboardInterrupt:
            print '\n\n\nby by !\n\n\n'
            break
        except :
            print colR + 'Error socket recvfrom client' + colD
            break
   
  


if __name__ == '__main__':

    print colR+Hello_Word+colD
    args = parse_args()
    run(args.ipLocal, args.resolver, args.nocolor, args.silence)


