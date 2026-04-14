#!/bin/sh

CURRDIR="$PWD"
mkdir -p "$CURRDIR/llvm_func_pass/build"
cd "$CURRDIR/llvm_func_pass/build"
cmake ..
make

mkdir -p "$CURRDIR/llvm_ext_sym_pass/build"
cd "$CURRDIR/llvm_ext_sym_pass/build"
cmake ..
make

mkdir -p "$CURRDIR/llvm_policy_pass/build"
cd "$CURRDIR/llvm_policy_pass/build"
cmake ..
make

cd "$CURRDIR"
