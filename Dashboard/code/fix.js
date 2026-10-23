const fs = require('fs');
let s = fs.readFileSync('script.js', 'utf8');
s = s.replace(/A\xEF\xBF\xBD\s/g, '• ');
fs.writeFileSync('script.js', s);
