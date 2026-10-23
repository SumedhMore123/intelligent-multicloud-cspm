const fs = require('fs');

let styles = fs.readFileSync('styles.css', 'utf8');
let lines = styles.split('\n');
let newLines = [];
let keep = true;

for (let i = 0; i < lines.length; i++) {
  let line = lines[i].trimRight();
  
  // Stop when we hit the old dashboard stuff
  if (line.includes('MAIN DASHBOARD')) {
    keep = false;
  }
  
  if (keep) {
    // skip consecutive empty lines
    if (line.trim() === '' && (newLines.length === 0 || newLines[newLines.length - 1].trim() === '')) {
      continue;
    }
    newLines.push(line);
  }
}

fs.writeFileSync('styles.css', newLines.join('\n'));
console.log('styles.css trimmed to Base + IAM, lines:', newLines.length);
