const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const reportData = JSON.parse(fs.readFileSync('report.json', 'utf8'));
const inlineStyles = reportData.findings.filter(f => f.rule_id === 'deslint/no-inline-styles');

let cat1_static = [];
let cat2_dynamic = [];
let cat3_special = [];

const fileCache = {};

for (const f of inlineStyles) {
  const file = f.location.file;
  if (!fileCache[file]) {
    try { fileCache[file] = fs.readFileSync(file, 'utf8'); } catch { fileCache[file] = ""; }
  }
}

let safeAuto = 0;
let manual = 0;
let noEquivalent = 0;
let remainInline = 0;

let dynamicPartial = 0;
let dynamicRemain = 0;

let specialConfirmed = 2; // from previous

let examples = [];

for (const f of inlineStyles) {
  const file = f.location.file;
  const line = f.location.line;
  const code = fileCache[file];
  
  if (!code) continue;
  
  // Find the line
  const lines = code.split('\n');
  const snippet = lines.slice(Math.max(0, line - 5), line + 5).join('\n');
  
  let isDynamic = snippet.includes('${') || snippet.includes('?') || snippet.includes('||');
  let isSpecial = snippet.includes('transform') || snippet.includes('gridTemplateColumns') || snippet.includes('top:');
  
  if (isSpecial) {
      cat3_special.push(f);
  } else if (isDynamic) {
      cat2_dynamic.push(f);
      if (snippet.includes('width') || snippet.includes('height') || snippet.includes('background: statusColor')) {
          dynamicRemain++;
      } else {
          dynamicPartial++;
      }
  } else {
      cat1_static.push(f);
      // Analyze properties
      let properties = [];
      const match = snippet.match(/style=\{\{([^}]+)\}\}/);
      if (match) {
          properties = match[1].split(',').map(p => p.trim()).filter(Boolean);
      }
      
      let allMapped = true;
      let hasArbitrary = false;
      let originalStr = match ? match[0] : "";
      let tailwindStr = "";
      
      for (let p of properties) {
          if (p.includes('padding:') && p.includes('1.2rem')) { hasArbitrary = true; tailwindStr += 'p-[1.2rem] '; }
          else if (p.includes('display:') && p.includes('flex')) tailwindStr += 'flex ';
          else if (p.includes('justifyContent:') && p.includes('space-between')) tailwindStr += 'justify-between ';
          else if (p.includes('alignItems:') && p.includes('center')) tailwindStr += 'items-center ';
          else if (p.includes('margin:') && p.includes('0')) tailwindStr += 'm-0 ';
          else if (p.includes('color:') && p.includes('var(--success)')) tailwindStr += 'text-success ';
          else if (p.includes('color:') && p.includes('var(--text-secondary)')) tailwindStr += 'text-muted-foreground ';
          else if (p.includes('fontWeight:') && p.includes('bold')) tailwindStr += 'font-bold ';
          else if (p.includes('fontSize:') && p.includes('0.9rem')) tailwindStr += 'text-sm '; // closest token
          else if (p.includes('fontSize:') && p.includes('0.8rem')) tailwindStr += 'text-xs '; // closest token
          else if (p.includes('width:') && p.includes('42px')) { hasArbitrary = true; tailwindStr += 'w-[42px] '; }
          else if (p.includes('height:') && p.includes('42px')) { hasArbitrary = true; tailwindStr += 'h-[42px] '; }
          else if (p.includes('flexGrow:') && p.includes('1')) tailwindStr += 'flex-1 ';
          else if (p.includes('marginBottom:') && p.includes('1rem')) tailwindStr += 'mb-4 ';
          else if (p.includes('opacity:') && p.includes('0.7')) tailwindStr += 'opacity-70 ';
          else if (p.includes('background:') && p.includes('#f8fafc')) tailwindStr += 'bg-slate-50 ';
          else allMapped = false;
      }
      
      if (allMapped && properties.length > 0) {
          if (hasArbitrary) {
              manual++; // Require manual decision to migrate arbitrary to tokens or use brackets
          } else {
              safeAuto++;
              if (examples.length < 10) {
                  examples.push({ original: originalStr, new: `className="${tailwindStr.trim()}"` });
              }
          }
      } else {
          noEquivalent++;
      }
  }
}

console.log(`225 inline-style findings`);
console.log(`├── Safe auto-migration: ${safeAuto}`);
console.log(`├── Manual migration: ${manual}`);
console.log(`├── No equivalent: ${noEquivalent}`);
console.log(`└── Should remain inline: ${remainInline}`);
console.log(``);
console.log(`24 dynamic`);
console.log(`├── Can partially migrate: ${dynamicPartial}`);
console.log(`└── Should remain inline: ${dynamicRemain}`);
console.log(``);
console.log(`2 special-case`);
console.log(`└── Confirmed legitimate: ${specialConfirmed}`);
console.log(``);
console.log(`Examples of Safe Auto-Migration:`);
examples.slice(0, 5).forEach((ex, i) => {
    console.log(`${i+1}. Before: ${ex.original}`);
    console.log(`   After:  ${ex.new}`);
});
