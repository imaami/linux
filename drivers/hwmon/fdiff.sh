#!/usr/bin/env bash

fmt=(clang-format --style=file:"$(dirname "$0")/../../.clang-format")

diff -u -ZEBbw --color=always \
	<("${fmt[@]}" < "$1") \
	<("${fmt[@]}" < "$2") | less -RS
