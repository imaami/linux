#!/usr/bin/env bash

fmt=(clang-format --style=file:"$(dirname "$0")/../../.clang-format")

[[ -f "$1" && -f "$2" ]] &&
tmp="$(mktemp -d)"       &&
[[ -d "$tmp" ]]          &&
{
	a="a/${1##*/}"
	b="b/${2##*/}"
	unset out
	mkdir -p "$tmp/a" "$tmp/b"     &&
	"${fmt[@]}" < "$1" > "$tmp/$a" &&
	"${fmt[@]}" < "$2" > "$tmp/$b" &&
	pushd "$tmp" >/dev/null 2>&1   &&
	{
		out=$(git diff --color=always --no-index --no-prefix   \
		               --ignore-blank-lines --ignore-cr-at-eol \
		               --ignore-space-at-eol -b -w -- "$a" "$b")
		popd >/dev/null 2>&1
	}
	rm -fr "$tmp/"
	[[ "$out" ]] && less -R -S <<< "$out"
}
