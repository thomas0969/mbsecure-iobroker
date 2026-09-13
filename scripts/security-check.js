'use strict';

const fs = require('fs');
const path = require('path');

const roots = ['src', 'docs', '.github'];
const forbidden = [
    /192\.168\.100\.252/g,
    /password\s*:\s*['"]pw['"]/gi,
    /Cosimastra/gi,
    /Thomas\s+Wirsum/gi,
    /Jan\s+Cedrik\s+Wirsum/gi
];

const files = [];

function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else files.push(full);
    }
}

roots.forEach(walk);

let failed = false;
for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const pattern of forbidden) {
        pattern.lastIndex = 0;
        if (pattern.test(text)) {
            console.error(`Potential private value found in ${file}: ${pattern}`);
            failed = true;
        }
    }
}

if (failed) process.exit(1);
console.log('Security check: no known private values found.');
