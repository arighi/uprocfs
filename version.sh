#!/bin/sh

version=`git describe --tags`

if git diff-index --name-only HEAD | read dummy; then
	version="$version-dirty"
fi
if [ ! -z "$version" ]; then
	echo "m4_define([VERSION_NUMBER], [$version])" > version.m4
fi
