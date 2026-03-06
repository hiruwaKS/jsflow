#!/usr/bin/env node
const fs = require('fs');
const esprima = require('esprima');
sourceCode = fs.readFileSync(process.argv[2], 'utf8');
sourceCode = sourceCode.replace(/^#!.*\n/, '\n');
sourceCode = sourceCode.replace(/\r\n/g, '\n');
root = esprima.parseModule(sourceCode, { loc: true, range: true, tolerant: true});
if (root.errors && root.errors.length > 0) console.error('error');