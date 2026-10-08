/* Source-position-aware structural scanners; no reserialization. */
(function(root){
'use strict';
function csv(text,delimiter=','){
 const rows=[];let row=[],start=0,quoted=false,atFieldStart=true;
 function field(end){let lo=start,hi=end;if(text[lo]==='"'&&text[hi-1]==='"'){lo++;hi--}row.push({start:lo,end:hi,value:text.slice(lo,hi).replace(/""/g,'"')})}
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(c==='"'){if(quoted&&text[i+1]==='"'){i++;continue}if(atFieldStart||quoted)quoted=!quoted}
  if(!quoted&&(c===delimiter||c==='\n'||c==='\r')){
   field(i);atFieldStart=true;start=i+1;
   if(c!==delimiter){rows.push(row);row=[];if(c==='\r'&&text[i+1]==='\n'){i++;start++}}
  }else if(atFieldStart&&c!=='"')atFieldStart=false;
 }
 if(start<text.length||row.length){field(text.length);rows.push(row)}
 return rows;
}
function json(text,offset=0){
 let p=0;const nodes=[];
 const whitespace=()=>{while(/\s/.test(text[p]||'')&&p<text.length)p++};
 function string(){
  const start=p++;let decoded='';
  for(;p<text.length;){const c=text[p++];if(c==='"')break;if(c==='\\'){const n=text[p++];if(n==='u'){const digits=text.slice(p,p+4);p+=4;decoded+=String.fromCharCode(parseInt(digits,16))}else decoded+=({'n':'\n','r':'\r','t':'\t','b':'\b','f':'\f','/':'/','\\':'\\','"':'"'}[n]??n)}else decoded+=c}
  return {start:start+1,end:p-1,value:decoded,rawStart:start,rawEnd:p}
 }
 function value(path){
  whitespace();const c=text[p];if(c==='"'){const s=string();nodes.push({...s,start:s.start+offset,end:s.end+offset,path,kind:'string'});return}
  if(c==='{'){p++;whitespace();while(text[p]!=='}'&&p<text.length){const key=string();whitespace();if(text[p++]!==':')throw Error('Expected colon');value(path.concat(key.value));whitespace();if(text[p]===','){p++;whitespace();continue}break}if(text[p++]!=='}')throw Error('Expected }');return}
  if(c==='['){p++;whitespace();let index=0;while(text[p]!==']'&&p<text.length){value(path.concat(index++));whitespace();if(text[p]===','){p++;whitespace();continue}break}if(text[p++]!==']')throw Error('Expected ]');return}
  const start=p;while(p<text.length&&!/[,}\]\s]/.test(text[p]))p++;if(p===start)throw Error('Expected value');
  nodes.push({start:start+offset,end:p+offset,value:text.slice(start,p),path,kind:'literal'})
 }
 whitespace();value([]);whitespace();if(p!==text.length)throw Error('Trailing data');return nodes;
}
function jsonPath(path){return '$'+path.map(s=>typeof s==='number'?'['+s+']':"['"+String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'")+"']").join('')}
function pathPattern(path){return '$'+path.map(s=>typeof s==='number'?'[*]':"['"+String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'")+"']").join('')}
const api={csv,json,jsonPath,pathPattern};
if(typeof module!=='undefined'&&module.exports)module.exports=api;root.AnonymiseStructure=api;
})(typeof globalThis!=='undefined'?globalThis:this);
