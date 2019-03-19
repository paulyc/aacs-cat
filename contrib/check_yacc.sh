#!/bin/bash

if [ -z "$YACC" ]; then
  YACC=`which yacc`
fi

if [ -z "$YACC" ]; then
  YACC="`which bison` -y"
fi

BISON_TWO=$($YACC --version|grep 'bison (GNU Bison) 2')
if [ "$BISON_TWO" ]; then
  echo "yacc or bison 3 is required"
  exit 1
fi
