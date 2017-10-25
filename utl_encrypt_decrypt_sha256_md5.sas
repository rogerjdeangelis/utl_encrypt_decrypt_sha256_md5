 De identifying or anonymize data. Examples of some encryption techniques


        Note SAS function UUIDGEN can generate globally unique IDs

        MD5 does work in SAS/WPS and R
        MD5 is no longer secure as a cryptographic hash function?
        https://stackoverflow.com/questions/2117732/reasons-why-sha512-is-superior-to-md5
        sha256 and sha512 are not available in base SAS/WPS, but are in open source R

        WORKING CODE

           Three solutions

          1. One way hash  (you need SAS secure for sha256 - however you can use md5)
             SAS -- ERROR: SHA256 not available. SAS/SECURE not installed?
             WPS -- Function SHA256 is not vailable

               length ssnhash $ 32;
               format ssnhash $hex64.;
               ssnhash = sha256(ssn);

          2. R package "digest" - All of these work? sha1, sha256, sha512, md4, md5 and ripemd160

                have$SSNMD5<-sha256(have$SSN);  /* other hashes available */


          2. Weak two wany algorithm (only works well on large integers)

             res=encrypt(ssn);
             round_trip_ssn=decrypt(res);

             DETAILS

              ENCRYPT

               key=8192;
               ssn_remainder = mod(ssn, key);
               ssn_int       = round((ssn - ssn_remainder)/key,1);
               * 8192  ssn_remainder = 1 and ssn_int = 1 ie 1*key + 1 = original value;
               ssn_big   = ssn_int*100000 + ssn_remainder;
               rev=reverse(putn(ssn_big,16.));
               ssn_encrypt=input(rev,16.);

              DECRYPT

               length rev $16;
               key=8192;
               rev=reverse(putn(ssn,16.));
               ssn_big=input(rev,16.);
               ssn_decrypt   = round(ssn_big/100000,1)*key + mod(ssn_big,10000);


https://goo.gl/3yf57W
https://communities.sas.com/t5/Base-SAS-Programming/How-do-I-create-an-ID-variable-accounting-for-duplicates/m-p/391210

andreas_lds profile
https://communities.sas.com/t5/user/viewprofilepage/user-id/15475


HAVE

 Up to 40 obs WORK.HAVE total obs=4

 Obs      SSN       CHILD

  1     11122333      1
  2     44455666      1
  3     77788999      1
  4     77788999      2


WANT
====

SHA256

Up to 40 obs from have total obs=4

Obs      SSN       CHILD                               SSNSHA256

 1     11122333      1      5b08fef75f3f8d1d07adac0043a36aa93657c8eb0a28f262402786c185e1ec3b
 2     44455666      1      2b08156843d0526557a8772a40e4402c0db02ed69dbf6ea980bc371096846e11
 3     77788999      1      efef82ca496455af2ad0462c3d2f361bdac74c6fc0f7f949510a7241f14e61af
 4     77788999      2      efef82ca496455af2ad0462c3d2f361bdac74c6fc0f7f949510a7241f14e61af


VERY WEAK REVERSIBLE


Up to 40 obs from want total obs=16

Obs       SSN         ENCRYPT       DECRYPT

 13    111223333     9450077531    111223333
 14    444556666     2041076245    444556666
 15    777889999     5522075949    777889999
 16    777889999     5522075949    777889999


*                _              _       _
 _ __ ___   __ _| | _____    __| | __ _| |_ __ _
| '_ ` _ \ / _` | |/ / _ \  / _` |/ _` | __/ _` |
| | | | | | (_| |   <  __/ | (_| | (_| | || (_| |
|_| |_| |_|\__,_|_|\_\___|  \__,_|\__,_|\__\__,_|

;

data have;
input ssn $ child;
cards4;
111223333 1
444556666 1
777889999 1
777889999 2
;;;;
run;quit;

*          _       _   _
 ___  ___ | |_   _| |_(_) ___  _ __  ___
/ __|/ _ \| | | | | __| |/ _ \| '_ \/ __|
\__ \ (_) | | |_| | |_| | (_) | | | \__ \
|___/\___/|_|\__,_|\__|_|\___/|_| |_|___/

;
data want;

   set have;

   length ssnhash $ 32;
   format ssnhash $hex64.;

   ssnhash = sha256(ssn);

run;quit;
ERROR: SHA256 not available. SAS/SECURE not installed?

*____
|  _ \
| |_) |
|  _ <
|_| \_\

;

%utl_submit_wps64('
libname sd1 "d:/sd1";
options set=R_HOME "C:/Program Files/R/R-3.4.0";
libname wrk "%sysfunc(pathname(work))";
proc r;
submit;
source("c:/Program Files/R/R-3.4.0/etc/Rprofile.site",echo=T);
library(haven);
library(openssl);
library(digest);
have<-read_sas("d:/sd1/have.sas7bdat");
have;
have$SSNSHA256<-sha256(have$SSN);
have;
endsubmit;
import r=have data=wrk.have;
run;quit;
');


Up to 40 obs from have total obs=4

Obs      SSN       CHILD                               SSNSHA256

 1     11122333      1      5b08fef75f3f8d1d07adac0043a36aa93657c8eb0a28f262402786c185e1ec3b
 2     44455666      1      2b08156843d0526557a8772a40e4402c0db02ed69dbf6ea980bc371096846e11
 3     77788999      1      efef82ca496455af2ad0462c3d2f361bdac74c6fc0f7f949510a7241f14e61af
 4     77788999      2      efef82ca496455af2ad0462c3d2f361bdac74c6fc0f7f949510a7241f14e61af


*                   _                                   _ _     _
__      _____  __ _| | __   _ __ _____   _____ _ __ ___(_) |__ | | ___
\ \ /\ / / _ \/ _` | |/ /  | '__/ _ \ \ / / _ \ '__/ __| | '_ \| |/ _ \
 \ V  V /  __/ (_| |   <   | | |  __/\ V /  __/ |  \__ \ | |_) | |  __/
  \_/\_/ \___|\__,_|_|\_\  |_|  \___| \_/ \___|_|  |___/_|_.__/|_|\___|

;

* you need to change the key;


%let cmplib = %sysfunc(getoption(cmplib));
%let cmplib = %sysfunc(getoption(cmplib));
options cmplib = (work.functions /*&cmplib*/);

options fmtsearch=(work.formats mta.mta_formats_v1f mta.var2des);
proc fcmp outlib=work.functions.hashssn;
function encrypt(ssn);
    length rev $17;
    key=8192;
    ssn_remainder = mod(ssn, key);
    ssn_int       = round((ssn - ssn_remainder)/key,1);
    * 8192  ssn_remainder = 1 and ssn_int = 1 ie 1*key + 1 = original value;
    ssn_big   = ssn_int*100000 + ssn_remainder;
    rev=reverse(put(ssn_big,17.));
    if substr(rev,1,1)=0 then rev=cats('-1',substr(rev,2));
    ssn_encrypt=input(rev,17.);
  return(ssn_encrypt);
endsub;
run;quit;

proc fcmp outlib=work.functions.hashssn;
function decrypt(ssn);
    length rev $17;
    key=8192;
    rev=strip(reverse(put(ssn,17.)));
    if index(rev,'-')>0 then substr(rev,index(rev,'-')-1)='0 ';
    ssn_big=input(rev,17.);
    ssn_decrypt   = round(ssn_big/100000,1)*key + mod(ssn_big,10000);
  return(ssn_decrypt);
endsub;
;run;quit;


data want;

  set have;

  res=encrypt(ssn);
  round_trip_ssn=decrypt(res);

run;quit;


