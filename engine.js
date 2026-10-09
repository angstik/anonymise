/* Pure privacy engine: deterministic type-preserving pseudonyms and contextual grouping. */
(function(root){
'use strict';
const alphabet='abcdefghjkmnpqrstuvwxyz';
function hash(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return h>>>0}
let salt='';
function setSalt(value){salt=String(value||'')}
function getSalt(){return salt}
function pseudonym(value,type='other'){
 const seed=hash(salt+'\u0000'+type+'\u0000'+value);
 let out='',k=0;
 for(const c of value){
  let n=hash(seed+':'+k++);
  if(/[0-9]/.test(c))out+=String((n%9+1)%10);
  else if(/[a-z]/.test(c))out+=alphabet[n%alphabet.length];
  else if(/[A-Z]/.test(c))out+=alphabet[n%alphabet.length].toUpperCase();
  else if(/\p{Ll}/u.test(c))out+=alphabet[n%alphabet.length];
  else if(/\p{Lu}/u.test(c))out+=alphabet[n%alphabet.length].toUpperCase();
  else out+=c;
 }
 // Preserve shape but avoid returning an unchanged sensitive value.
 if(out===value&&value.length&&/[a-zA-Z0-9]/.test(value[0])){
   const first=value[0];out=(/[0-9]/.test(first)?String((Number(first)+1)%10):/[A-Z]/.test(first)?'X':'x')+out.slice(1);
 }
 return out;
}
function normalPath(path){
 return path.replace(/\|cell:[A-Z]+\d+/g,'').replace(/\s*\[row\s+\d+\]/gi,'').replace(/#text\[\d+\]/g,'#text[*]').replace(/\[\d+\]/g,'[*]');
}
function context(zone){
 const loc=zone.locator||'';
 // Regex matches in free text can share a rule; typed structured paths never cross fields.
 const mode=loc.startsWith('regex:')?'regex':loc.startsWith('column:')?'column':loc.startsWith('part:')?'office':loc.startsWith('$')?'json':loc.startsWith('/')?'xml':'offset';
 return mode+'|'+zone.type+'|'+normalPath(loc)+'|'+(zone.origin==='manual'?'manual':'detected');
}
function groups(zones){
 const m=new Map();for(const z of zones){const key=context(z);if(!m.has(key))m.set(key,[]);m.get(key).push(z)}return [...m.values()];
}
function sameOccurrences(source,value,positions,existing){
 if(!value||!positions.length)return [];
 const found=[];for(const p of positions){if(p.end-p.start<value.length)continue;let pos=p.start;while((pos=source.indexOf(value,pos))!==-1&&pos+value.length<=p.end){const end=pos+value.length;if(!existing.some(z=>z.start<end&&z.end>pos))found.push({start:pos,end,locator:p.locator});pos=end}}
 return found;
}
const api={pseudonym,normalPath,context,groups,sameOccurrences,setSalt,getSalt};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.AnonymiseEngine=api;
})(typeof globalThis!=='undefined'?globalThis:this);
