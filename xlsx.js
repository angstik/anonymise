/* XLSX worksheet reader/writer. Existing XML parts are retained; only changed cells are rewritten. */
(function(root){
'use strict';
const decode=s=>s.replace(/&#x([a-f0-9]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16))).replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(+n)).replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&');
const escape=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
function colIndex(ref){let n=0;for(const c of ref.match(/^[A-Z]+/)?.[0]||'')n=n*26+c.charCodeAt(0)-64;return n-1}
function colName(n){let name='';for(n++;n;n=Math.floor((n-1)/26))name=String.fromCharCode(65+(n-1)%26)+name;return name}
function sharedStrings(xml){return [...xml.matchAll(/<si(?:\s[^>]*)?>([\s\S]*?)<\/si>/g)].map(m=>[...m[1].matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map(t=>decode(t[1])).join(''))}
function sheetCells(part,strings){
 const result=[];const xml=part.xml||'',re=/<c\b([^>]*\br="([A-Z]+[1-9]\d*)"[^>]*)(?:>([\s\S]*?)<\/c>|\/>)/g;let m;
 while((m=re.exec(xml))){
  const attr=m[1],body=m[3]||'',ref=m[2],type=/\bt="([^"]+)"/.exec(attr)?.[1]||'';
  const formula=/<f(?:\s|>)/.test(body);const v=/<v(?:\s[^>]*)?>([\s\S]*?)<\/v>/.exec(body);
  const ts=[...body.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)];
  let value='';
  if(type==='s'&&v)value=strings[Number(v[1])]||'';
  else if(type==='inlineStr')value=ts.map(t=>decode(t[1])).join('');
  else if(v)value=decode(v[1]);
  if(!value||formula)continue;
  result.push({ref,row:Number(ref.match(/\d+/)[0]),col:colIndex(ref),value,type,part:part.name,xmlStart:m.index,xmlEnd:re.lastIndex,raw:m[0],attrs:attr,formula});
 }
 return result;
}
function build(parts){
 const shared=parts.find(p=>p.name==='xl/sharedStrings.xml');
 const strings=shared?sharedStrings(shared.xml||new TextDecoder().decode(shared.content)):[];
 const sheets=parts.filter(p=>/^xl\/worksheets\/sheet\d+\.xml$/.test(p.name)).sort((a,b)=>Number(a.name.match(/sheet(\d+)/)[1])-Number(b.name.match(/sheet(\d+)/)[1]));
 const result={source:'',spans:[],sheets:[],cells:[]};
 for(const part of sheets){
  const cells=sheetCells(part,strings),first=Math.min(...cells.map(c=>c.row)),headers=new Map(cells.filter(c=>c.row===first).map(c=>[c.col,c.value]));
  const byRow=new Map();
  for(const cell of cells){
   cell.header=headers.get(cell.col)||colName(cell.col);
   cell.isHeader=cell.row===first;
   cell.locator='sheet:'+part.name+'|column:'+colName(cell.col)+'|header:'+cell.header+'|cell:'+cell.ref;
   cell.start=result.source.length;result.source+=cell.value;cell.end=result.source.length;result.source+='\n';
   result.spans.push({start:cell.start,end:cell.end,part:part.name,cell,locator:cell.locator});
   result.cells.push(cell);
   if(!byRow.has(cell.row))byRow.set(cell.row,[]);
   byRow.get(cell.row).push(cell);
  }
  result.sheets.push({name:part.name.match(/sheet\d+/)[0],part:part.name,headers:[...headers.entries()].sort((a,b)=>a[0]-b[0]).map(([col,label])=>({col,letter:colName(col),label})),rows:[...byRow.entries()].sort((a,b)=>a[0]-b[0]).map(([number,cells])=>({number,cells}))});
 }
 return result;
}
function modifyPart(part,cells,zones,mask){
 let xml=part.xml;const changes=[];
 for(const cell of cells){
  const associated=zones.filter(z=>z.strategy!=='keep'&&z.start<cell.end&&z.end>cell.start);
  if(!associated.length)continue;
  let value=cell.value;
  for(const z of associated.sort((a,b)=>b.start-a.start)){
   const begin=Math.max(cell.start,z.start)-cell.start,end=Math.min(cell.end,z.end)-cell.start;
   const original=value.slice(begin,end);
   value=value.slice(0,begin)+(z.strategy==='redact'?'[REDACTED]':mask(original,z.type))+value.slice(end);
  }
  if(value===cell.value)continue;
  // Shared strings are NOT edited: convert only this cell to inline string.
  // Numeric cells retain their numeric kind if the replacement is numeric.
  const numeric=(cell.type===''||cell.type==='n')&&/^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(value);
  let attrs=cell.attrs.replace(/\s+t="[^"]*"/,'');
  const replacement=numeric?'<c'+attrs+'><v>'+escape(value)+'</v></c>':'<c'+attrs+' t="inlineStr"><is><t xml:space="preserve">'+escape(value)+'</t></is></c>';
  changes.push({start:cell.xmlStart,end:cell.xmlEnd,replacement});
 }
 for(const change of changes.sort((a,b)=>b.start-a.start))xml=xml.slice(0,change.start)+change.replacement+xml.slice(change.end);
 return xml;
}
const api={build,modifyPart,colName,colIndex};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.AnonymiseXlsx=api;
})(typeof globalThis!=='undefined'?globalThis:this);
