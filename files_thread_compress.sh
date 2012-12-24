#!/bin/bash
f1=""
f2=""
f3=""
f0=""
count="0"
DIR=""
while getopts :d: OPTION
do
 case $OPTION in
 d)DIR=$OPTARG
  ;;
 :)
  echo "Option -$OPTARG requires an argument." >&2
  exit 1
 ;;
 esac
done

for i in `ls $DIR`
do
   if echo $i | egrep '(.sh|.py|.png|.gz|.bz2|.lzma)' > /dev/null; then
       echo "ff" > /dev/null
   else
       count=`expr $count + 1`
#       echo $i
       case $count in
       1)f0="$f0 $DIR/$i"
       ;;
       2)f1="$f1 $DIR/$i"
       ;;
       3)f2="$f2 $DIR/$i"
       ;;
       4)f3="$f3 $DIR/$i"
       ;;
       5)count=0
       esac
   fi
#    echo $i
done
lzma -9e $f0 &
lzma -9e $f1 &
lzma -9e $f2 &
lzma -9e $f3 &
