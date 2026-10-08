
const $ = id => document.getElementById(id);
const state={source:'',name:'',encoding:'utf-8',bom:new Uint8Array(),newline:'LF',format:'TEXT',zones:[],selected:null,csvDelimiter:',',truncated:false,office:null};
const CATEGORIES={credential:'Credential',email:'E-mail',phone:'Téléphone',ip:'Adresse IP',personal:'Information personnelle',other:'Autre donnée'};
const SECRET=/(?:pass(?:word|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth(?:orization)?|client[_-]?secret|private[_-]?key|bearer|credential|session[_-]?id|iban|ssn|social[_-]?security|num[eé]ro[_ -]?de[_ -]?s[eé]curit[eé]|nss)/i;
const PERSONAL=/(?:e[-_]?mail|courriel|first[_-]?name|last[_-]?name|full[_-]?name|given[_-]?name|surname|pr[eé]nom|nom[_-]?de[_-]?famille|birth(?:day|date)?|date[_-]?de[_-]?naissance|address|adresse|postal|zip[_-]?code|t[eé]l[eé]phone|mobile|passport|passeport|national[_-]?id|tax[_-]?id|customer[_-]?id|user[_-]?id|city|ville|street|rue|firstname|lastname|nom|name|zipcode|code[_-]?postal|dob)/i;
const ruleSets=[
 {type:'credential',regex:/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g},
 {type:'credential',regex:/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g},
 {type:'credential',regex:/\b(?:sk_(?:live|test)_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{25,})\b/g},
 {type:'credential',regex:/\bBearer[ \t]+[A-Za-z0-9._~+/=-]{10,}/gi,group:0},
 {type:'credential',regex:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g},
 {type:'email',regex:/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi},
 {type:'phone',regex:/(?<![\w])(?:\+?\d[\d .()-]{7,}\d)(?![\w])/g,validate:v=>{const digits=v.replace(/\D/g,'');return digits.length>=9&&digits.length<=15&&!/^\d{4}[- /.]\d{2}[- /.]\d{2}$/.test(v)}},
 {type:'ip',regex:/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,validate:v=>v.split('.').every(n=>Number(n)<=255)}
];
let noticeTimer;
function toast(message){$('toast').textContent=message;$('toast').classList.add('show');clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>$('toast').classList.remove('show'),3400)}
function escapeHTML(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function lineAt(offset){let n=1;for(let i=0;i<offset;i++)if(state.source.charCodeAt(i)===10)n++;return n}
function detectFormat(name,text){const ext=name.toLowerCase().split('.').pop();if(['json','jsonl'].includes(ext))return ext.toUpperCase();if(ext==='xml'||/^\s*<\?xml\b/.test(text))return 'XML';if(ext==='csv'||ext==='tsv')return 'CSV';if(/^\s*[\[{]/.test(text)){try{JSON.parse(text);return 'JSON'}catch{}}return 'TEXT'}
function readEncoding(bytes){
 let encoding='utf-8',skip=0;
 if(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf){skip=3}
 else if(bytes[0]===0xff&&bytes[1]===0xfe){encoding='utf-16le';skip=2}
 else if(bytes[0]===0xfe&&bytes[1]===0xff){encoding='utf-16be';skip=2}
 else if(bytes.length>5){let even=0,odd=0;for(let i=0;i<Math.min(bytes.length,4096);i++)if(bytes[i]===0)(i%2?odd++:even++);if(odd>even*3&&odd>20)encoding='utf-16le';else if(even>odd*3&&even>20)encoding='utf-16be'}
 let content;
 try{content=new TextDecoder(encoding,{fatal:true}).decode(bytes.subarray(skip))}
 catch{encoding='windows-1252';content=new TextDecoder(encoding).decode(bytes.subarray(skip))}
 return {content,encoding,bom:bytes.slice(0,skip)}
}
function encodeText(text){
 let bytes;
 if(state.encoding==='utf-8')bytes=new TextEncoder().encode(text);
 else if(state.encoding.startsWith('utf-16')){const little=state.encoding==='utf-16le';bytes=new Uint8Array(text.length*2);for(let i=0;i<text.length;i++){const n=text.charCodeAt(i);bytes[2*i]=little?n&255:n>>8;bytes[2*i+1]=little?n>>8:n&255}}
 else {const chars={'€':128,'‚':130,'ƒ':131,'„':132,'…':133,'†':134,'‡':135,'ˆ':136,'‰':137,'Š':138,'‹':139,'Œ':140,'Ž':142,'‘':145,'’':146,'“':147,'”':148,'•':149,'–':150,'—':151,'˜':152,'™':153,'š':154,'›':155,'œ':156,'ž':158,'Ÿ':159};bytes=new Uint8Array(text.length);for(let i=0;i<text.length;i++){const c=text[i].charCodeAt(0);if(c<=255&&!(c>=128&&c<=159))bytes[i]=c;else if(chars[text[i]]!==undefined)bytes[i]=chars[text[i]];else throw Error('Un caractère ne peut pas être réencodé en Windows-1252. Choisissez le masquage structurel.')} }
 const output=new Uint8Array(state.bom.length+bytes.length);output.set(state.bom);output.set(bytes,state.bom.length);return output
}
function sniffDelimiter(text){const sample=text.split(/\r?\n/).slice(0,12).join('\n');let best=',',score=-1;for(const d of [',',';','\t','|']){const n=sample.split(d).length-1;if(n>score){score=n;best=d}}return best}
function jsonQuoteDecode(s){try{return JSON.parse('"'+s+'"')}catch{return s}}
function jsonStringRanges(text){
 const result=[];const token=/"(?:\\.|[^"\\])*"/g;let match;
 while((match=token.exec(text))){let p=token.lastIndex;while(/\s/.test(text[p]||'')&&p<text.length)p++;if(text[p]===':')result.push({key:jsonQuoteDecode(match[0].slice(1,-1)),keyEnd:p,valueStart:p+1})}
 return result
}
function jsonLocator(text,index,key){const prefix=text.slice(0,index);const safe=String(key).replace(/\\/g,'\\\\').replace(/'/g,"\\'");return "$..['"+safe+"']"}
function addCandidate(out,start,end,type,locator,confidence='heuristic',origin='automatic'){
 if(!Number.isFinite(start)||!Number.isFinite(end)||start<0||end>state.source.length||end<=start)return;
 const v=state.source.slice(start,end);if(!v.trim())return;
 out.push({start,end,type,locator,confidence,origin,strategy:'mask'});
}
function scanStructure(out){
 const text=state.source,fmt=state.format;
 if(fmt==='JSON'||fmt==='JSONL'){
  try{
   const nodes=fmt==='JSON'?AnonymiseStructure.json(text):text.split(/\r?\n/).flatMap((line,i,all)=>{if(!line.trim())return [];const offset=all.slice(0,i).reduce((n,x)=>n+x.length+1,0);try{return AnonymiseStructure.json(line,offset)}catch{return []}});
   state.structuredNodes=nodes;
   for(const n of nodes){const key=String(n.path.at(-1)??'');const type=SECRET.test(key)?'credential':PERSONAL.test(key)?'personal':null;if(type)addCandidate(out,n.start,n.end,type,AnonymiseStructure.jsonPath(n.path),'key')}
  }catch(err){state.structuredNodes=[];console.warn('JSON malformed; regex fallback',err)}
 }else if(fmt==='XML'){
  const element=/<([A-Za-z_][\w:.-]*)(?:\s[^<>]*?)?>([^<>]+)<\/\1\s*>/g;let m;
  while((m=element.exec(text))){const type=SECRET.test(m[1])?'credential':PERSONAL.test(m[1])?'personal':null;if(type){const p=m.index+m[0].indexOf(m[2]);addCandidate(out,p,p+m[2].length,type,'//'+m[1]+'/text()','key')}}
  const attr=/([A-Za-z_:][\w:.-]*)\s*=\s*(["'])(.*?)\2/g;
  while((m=attr.exec(text))){const type=SECRET.test(m[1])?'credential':PERSONAL.test(m[1])?'personal':null;if(type){const p=m.index+m[0].lastIndexOf(m[3]);addCandidate(out,p,p+m[3].length,type,'//@'+m[1],'key')}}
 }else if(fmt==='CSV'){
  const d=state.csvDelimiter=sniffDelimiter(text),rows=AnonymiseStructure.csv(text,d);state.csvRows=rows;
  const header=rows[0]||[];
  for(let r=1;r<rows.length;r++)for(let c=0;c<rows[r].length;c++){const key=header[c]?.value||'';const type=SECRET.test(key)?'credential':PERSONAL.test(key)?'personal':null;if(type)addCandidate(out,rows[r][c].start,rows[r][c].end,type,'column:'+key+' [row '+(r+1)+']','column')}
 }
}
function scanGeneric(out){
 const text=state.source;
 for(const rule of ruleSets){rule.regex.lastIndex=0;let m;while((m=rule.regex.exec(text))){if(m[0].length===0){rule.regex.lastIndex++;continue}if(rule.validate&&!rule.validate(m[0]))continue;addCandidate(out,m.index,m.index+m[0].length,rule.type,'regex:'+rule.regex.source,'pattern')}}
 if(state.format==='TEXT'){
  const credentials=/(?:^|[\s,{])([A-Za-z][\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|authorization|credential)[\w.-]*)\s*[:=]\s*(["']?)([^\s,'"}#;]+)\2/gim;let m;
  while((m=credentials.exec(text))){const value=m[3];const pos=m.index+m[0].lastIndexOf(value);addCandidate(out,pos,pos+value.length,'credential','regex:'+m[1],'key')}}
}
function analyze(){
 const candidates=[];scanStructure(candidates);scanGeneric(candidates);
 const priority={credential:5,email:4,phone:3,ip:2,personal:1,other:0};
 candidates.sort((a,b)=>a.start-b.start||priority[b.type]-priority[a.type]||b.end-a.end);
 const accepted=[];for(const z of candidates){let intersects=false;for(const prev of accepted){if(prev.start<z.end&&prev.end>z.start){intersects=true;break}}if(!intersects)accepted.push(z)}
 state.zones=accepted.map((z,i)=>({...z,id:i+1}));if(state.office)for(const z of state.zones){const sp=state.office.spans.find(s=>z.start>=s.start&&z.end<=s.end);if(sp)z.locator='part:'+sp.part+'#text['+(state.office.spans.indexOf(sp)+1)+']'}state.selected=state.zones[0]?.id||null;render();
}
function masked(value,type){return AnonymiseEngine.pseudonym(value,type)}
function legacyMasked(value,type){
 let seed=0;for(let i=0;i<value.length;i++)seed=(Math.imul(seed,33)+value.charCodeAt(i))|0;
 const letters='abcdefghjkmnpqrstuvwxyz',digits='0123456789';
 return Array.from(value,(c,i)=>{const n=Math.abs((seed+i*71+i*i*13)|0);if(/[0-9]/.test(c))return digits[n%10];if(/[A-Z]/.test(c)||(/\p{Lu}/u.test(c)))return letters[n%letters.length].toUpperCase();if(/[a-z]/.test(c)||(/\p{Ll}/u.test(c)))return letters[n%letters.length];return c}).join('');
}
function replacement(z){const raw=state.source.slice(z.start,z.end);if(z.strategy==='keep')return raw;if(z.strategy==='redact')return '[REDACTED]';return masked(raw,z.type)}
function sanitize(){let result=state.source;for(const z of state.zones.filter(z=>z.strategy!=='keep').sort((a,b)=>b.start-a.start))result=result.slice(0,z.start)+replacement(z)+result.slice(z.end);return result}
function download(name,bytes,mime){const url=URL.createObjectURL(new Blob([bytes],{type:mime}));const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
function report(){return {schema:'anonymise-report/v1',version:'1.0.0',file:state.name,format:state.format,encoding:state.encoding,bom:Array.from(state.bom),sourceLength:state.source.length,generatedAt:new Date().toISOString(),offsetUnit:'UTF-16 code units',zones:state.zones.map(z=>({id:z.id,category:z.type,start:z.start,end:z.end,line:lineAt(z.start),locator:z.locator,locatorKind:z.locator.split(':')[0],strategy:z.strategy,applied:z.strategy!=='keep',origin:z.origin,confidence:z.confidence}))}}
function excludedSummary(){const ignored=state.zones.filter(z=>z.strategy==='keep');return {patterns:new Set(ignored.map(z=>AnonymiseEngine.context(z))).size,occurrences:ignored.length}}
function confirmExport(){const s=excludedSummary();return window.confirm('Exporter le document anonymisé ?\n\n'+s.patterns+' pattern(s), '+s.occurrences+' occurrence(s) explicitement exclue(s) du traitement.\nToutes les autres zones identifiées seront transformées.\n\nContinuer ?')}
function selectedZone(){return state.zones.find(z=>z.id===state.selected)}
function render(){
 $('countAll').textContent=state.zones.length;$('countActive').textContent=state.zones.filter(z=>z.strategy!=='keep').length;$('countIgnored').textContent=state.zones.filter(z=>z.strategy==='keep').length;$('format').textContent=state.format;$('zonesBadge').textContent=state.zones.length;
 const query=$('search').value.toLowerCase();$('zones').replaceChildren();const groups=new Map();for(const group of AnonymiseEngine.groups(state.zones))groups.set(AnonymiseEngine.context(group[0]),group);
 for(const group of groups.values()){const z=group[0];if(query&&!((CATEGORIES[z.type]||'')+' '+z.locator+' '+z.start).toLowerCase().includes(query))continue;
 const button=document.createElement('button');button.className='zone'+(z.id===state.selected?' selected':'')+(z.strategy==='keep'?' ignored':'');button.setAttribute('role','listitem');button.dataset.id=z.id;
 const name=document.createElement('div');name.className='label';const a=document.createElement('span');a.textContent=CATEGORIES[z.type]||z.type;const b=document.createElement('span');b.textContent=group.length>1?group.length+' occurrences':'L'+lineAt(z.start);name.append(a,b);const path=document.createElement('span');path.className='path';path.textContent=z.locator;const sample=document.createElement('span');sample.className='sample';sample.textContent=replacement(z).slice(0,36);button.append(name,path,sample);button.onclick=()=>{selectZone(z.id);$('groupActions').hidden=group.length<2;if(group.length>1){$('groupCount').textContent=group.length+' occurrences';$('groupApply').onclick=()=>{for(const q of group){q.strategy=$('strategy').value;q.type=$('category').value}render();toast('Groupe traité : '+group.length+' occurrences')};$('groupIgnore').onclick=()=>{for(const q of group)q.strategy='keep';render()}}};$('zones').append(button)}
 drawPreview();drawInspector();
}
function drawPreview(){
 const text=state.source,preview=$('preview'),limit=350000;
 state.truncated=text.length>limit;const clipped=text.slice(0,limit);
 let html='',index=0,line=1;const spans=state.zones.filter(z=>z.start<limit).sort((a,b)=>a.start-b.start);
 const pieces=[];for(const z of spans){if(z.start>index)pieces.push({text:clipped.slice(index,z.start)});const e=Math.min(z.end,limit);pieces.push({text:clipped.slice(z.start,e),zone:z});index=e}if(index<clipped.length)pieces.push({text:clipped.slice(index)});
 let lines=[''];for(const piece of pieces){const parts=piece.text.split('\n');for(let i=0;i<parts.length;i++){if(i)lines.push('');const s=escapeHTML(parts[i]);if(piece.zone&&s)lines[lines.length-1]+='<mark class="mark '+piece.zone.type+(piece.zone.id===state.selected?' selected':'')+(piece.zone.strategy==='keep'?' ignored':'')+'" data-zone="'+piece.zone.id+'">'+s+'</mark>';else lines[lines.length-1]+=s}}
 html=lines.map((l,i)=>'<div class="line"><span class="line-no">'+(i+1)+'</span>'+l+'</div>').join('');
 preview.innerHTML=html||'<span class="line-no">1</span>';
 preview.querySelectorAll('[data-zone]').forEach(el=>el.onclick=()=>selectZone(Number(el.dataset.zone)));
 $('displayNotice').textContent=state.truncated?'Aperçu limité aux 350 000 premiers caractères · Export complet':'Vue source · Cliquez sur une zone pour l’inspecter';
}
function drawInspector(){const z=selectedZone();if(!z)$('groupActions').hidden=true;$('emptyInspector').hidden=!!z;$('inspectorContent').hidden=!z;if(!z){$('position').textContent='—';return}
 $('category').value=z.type;$('locator').textContent=z.locator;$('range').textContent=z.start+' → '+z.end+' · longueur '+(z.end-z.start);$('original').textContent=state.source.slice(z.start,z.end);$('replacement').textContent=replacement(z);$('strategy').value=z.strategy;$('position').textContent='Ligne '+lineAt(z.start)+' · Zone '+z.id+'/'+state.zones.length;
}
function selectZone(id,scroll=true){state.selected=id;render();if(scroll){const highlighted=$('preview').querySelector('.mark.selected');if(highlighted)highlighted.scrollIntoView({block:'center',behavior:'smooth'});$('zones').querySelector('.zone.selected')?.scrollIntoView({block:'nearest'})}}
function move(delta){const i=state.zones.findIndex(z=>z.id===state.selected);if(!state.zones.length)return;selectZone(state.zones[(i+delta+state.zones.length)%state.zones.length].id)}
function switchView(manual){$('manual').hidden=!manual;$('preview').hidden=manual;$('viewOriginal').classList.toggle('view-on',manual);$('viewHighlights').classList.toggle('view-on',!manual)}
function manualSegments(locator,start,end){const text=state.source;const segments=[];if(state.office){for(const s of state.office.spans)if(('part:'+s.part+'#text['+(state.office.spans.indexOf(s)+1)+']')===locator)segments.push({start:s.start,end:s.end,locator});return segments}if(state.format==='CSV'){if(state.csvRows){const column=locator.match(/^column:(.*) \[row \d+\]$/)?.[1];const head=state.csvRows[0]||[];const ix=head.findIndex(c=>c.value===column);if(ix>=0)return state.csvRows.slice(1).map((row,i)=>row[ix]&&{start:row[ix].start,end:row[ix].end,locator:'column:'+column+' [row '+(i+2)+']'}).filter(Boolean)}const rows=text.split(/\r?\n/);const column=locator.match(/^column:(.*) \[row \d+\]$/)?.[1];if(!column)return [{start,end,locator}];let off=0;const header=rows[0].split(state.csvDelimiter);const ix=header.indexOf(column);if(ix<0)return [{start,end,locator}];for(let i=1;i<rows.length;i++){const fields=rows[i].split(state.csvDelimiter),pre=fields.slice(0,ix).join(state.csvDelimiter);const s=off+((ix>0?pre.length+1:0));if(fields[ix]!==undefined)segments.push({start:s,end:s+fields[ix].length,locator:'column:'+column+' [row '+(i+1)+']'});off+=rows[i].length+(text.includes('\r\n')?2:1)}return segments}if((state.format==='JSON'||state.format==='JSONL')&&state.structuredNodes){const target=state.structuredNodes.find(n=>start>=n.start&&end<=n.end);if(target){const pattern=AnonymiseStructure.pathPattern(target.path);return state.structuredNodes.filter(n=>AnonymiseStructure.pathPattern(n.path)===pattern).map(n=>({start:n.start,end:n.end,locator:AnonymiseStructure.jsonPath(n.path)}))}}if(state.format==='JSON'||state.format==='JSONL'){const key=locator.match(/^\$\.\.\['(.*)'\]$/)?.[1];if(key){for(const m of jsonStringRanges(text)){if(m.key!==key)continue;const tail=text.slice(m.valueStart);const v=/^\s*"((?:\\.|[^"\\])*)"/.exec(tail);if(v){const s=m.valueStart+v[0].indexOf('"')+1;segments.push({start:s,end:s+v[1].length,locator})}}}return segments}if(state.format==='XML'){const tag=locator.match(/^\/\/([\w:.-]+)\/text\(\)$/)?.[1];if(tag){const pattern=new RegExp('<'+tag+'(?:\\s[^<>]*)?>([^<>]*)<\\/'+tag+'\\s*>','g');let m;while((m=pattern.exec(text))){const s=m.index+m[0].indexOf(m[1]);segments.push({start:s,end:s+m[1].length,locator})}}return segments}return [{start,end,locator}]}
function addManual(){const el=$('rawText'),start=el.selectionStart,end=el.selectionEnd;if(start===end){toast('Sélectionnez d’abord un passage dans le texte original.');return}if(state.zones.some(z=>z.start<end&&z.end>start)){toast('La sélection recoupe une zone existante. Modifiez ou supprimez-la d’abord.');return}
 const id=Math.max(0,...state.zones.map(z=>z.id))+1;let locator='range:'+start+'-'+end;if(state.office){const sp=state.office.spans.find(s=>start>=s.start&&end<=s.end);if(sp)locator='part:'+sp.part+'#text['+(state.office.spans.indexOf(sp)+1)+']'}else if(state.format==='CSV'){const cell=state.csvRows?.flatMap((row,i)=>row.map((c,j)=>({c,i,j}))).find(x=>start>=x.c.start&&end<=x.c.end);if(cell){locator='column:'+(state.csvRows[0]?.[cell.j]?.value||cell.j)+' [row '+(cell.i+1)+']'}else{const lines=state.source.slice(0,start).split(/\r?\n/);const row=lines.length;const col=lines.at(-1).split(state.csvDelimiter).length-1;const head=state.source.split(/\r?\n/)[0].split(state.csvDelimiter);locator='column:'+(head[col]||col)+' [row '+row+']'}}else if(state.format==='JSON'||state.format==='JSONL'){const node=state.structuredNodes?.find(n=>start>=n.start&&end<=n.end);if(node)locator=AnonymiseStructure.jsonPath(node.path);else{const m=[...state.source.slice(0,start).matchAll(/"((?:\\.|[^"\\])+)"\s*:\s*"/g)].pop();if(m)locator=jsonLocator(state.source,start,jsonQuoteDecode(m[1]))}}else if(state.format==='XML'){const m=[...state.source.slice(0,start).matchAll(/<([\w:.-]+)(?:\s[^<>]*)?>/g)].pop();if(m)locator='//'+m[1]+'/text()'}const fresh=[{id,start,end,type:'other',locator,confidence:'manual',origin:'manual',strategy:'mask'}];if(['CSV','JSON','JSONL','XML','DOCX','XLSX'].includes(state.format)&&$('allIdentical').checked){const value=state.source.slice(start,end);const segments=manualSegments(locator,start,end);const found=AnonymiseEngine.sameOccurrences(state.source,value,segments,state.zones);let next=id+1;for(const p of found){if(p.start!==start)fresh.push({id:next++,start:p.start,end:p.end,type:'other',locator:p.locator,confidence:'manual',origin:'manual',strategy:'mask'})}}state.zones.push(...fresh);state.zones.sort((a,b)=>a.start-b.start);switchView(false);selectZone(id);toast(fresh.length+' occurrence(s) ajoutée(s).')}
function attachEvents(){
 $('saltOpen').onclick=()=>showSalt(true);$('saltSave').onclick=saveSalt;$('saltInput').onkeydown=ev=>{if(ev.key==='Enter')saveSalt()};$('drop').onclick=()=>$('file').click();$('drop').onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file').click()}};
 $('drop').ondragover=e=>{e.preventDefault();$('drop').classList.add('dragging')};$('drop').ondragleave=()=>$('drop').classList.remove('dragging');
 $('drop').ondrop=e=>{e.preventDefault();$('drop').classList.remove('dragging');const file=e.dataTransfer.files[0];if(file)loadFile(file)};
 $('file').onchange=e=>{if(e.target.files[0])loadFile(e.target.files[0]);e.target.value=''};
 $('previous').onclick=()=>move(-1);$('next').onclick=()=>move(1);$('search').oninput=render;
 $('category').onchange=e=>{const z=selectedZone();if(z){z.type=e.target.value;render()}};
 $('strategy').onchange=e=>{const z=selectedZone();if(z){z.strategy=e.target.value;render()}};
 $('removeZone').onclick=()=>{const z=selectedZone();if(!z)return;z.strategy='keep';render();toast('Zone explicitement exclue du traitement et comptabilisée dans le bilan d’export.')};
 $('viewHighlights').onclick=()=>switchView(false);$('viewOriginal').onclick=()=>switchView(true);$('addSelection').onclick=addManual;
 $('reanalyze').onclick=()=>{if(confirm('Réanalyser le document ? Les corrections manuelles seront perdues.'))analyze()};
 $('exportFile').onclick=async()=>{if(!confirmExport())return;try{if(state.office){const blob=await exportOffice(state.office,state.zones,masked);download(state.name.replace(/(\.[^.]+)?$/,'-anonymise$1'),blob,'application/octet-stream')}else{const text=sanitize();download(state.name.replace(/(\.[^.]+)?$/,'-anonymise$1'),encodeText(text),'application/octet-stream')}toast('Copie anonymisée exportée.')}catch(e){toast(e.message)}};
 $('exportReport').onclick=()=>{if(!confirmExport())return;download(state.name+'-zones.json',new TextEncoder().encode(JSON.stringify(report(),null,2)),'application/json');toast('Rapport JSON exporté (sans valeurs originales).')};
 window.addEventListener('keydown',e=>{if(e.target.matches('input,textarea,select'))return;if(e.key==='ArrowDown'&&state.source){e.preventDefault();move(1)}if(e.key==='ArrowUp'&&state.source){e.preventDefault();move(-1)}});
}
async function loadFile(file){
 if(file.size>30*1024*1024&&!confirm('Ce fichier dépasse 30 Mo. L’analyse peut être lente. Continuer ?'))return;
 try{const bytes=new Uint8Array(await file.arrayBuffer());const officeFormat=/\.(docx|xlsx)$/i.exec(file.name)?.[1]?.toUpperCase();const office=officeFormat?await transformZip(bytes,officeFormat):null;const result=office?{content:office.source,encoding:'utf-8',bom:new Uint8Array()}:readEncoding(bytes);state.office=office;
 if(result.content.includes('\u0000')){toast('Fichier contenant des octets NUL : vérifiez qu’il s’agit bien d’un texte.')}
 state.source=result.content;state.name=file.name;state.encoding=result.encoding;state.bom=result.bom;state.format=officeFormat||detectFormat(file.name,result.content);
 state.newline=result.content.includes('\r\n')?'CRLF':result.content.includes('\r')?'CR':'LF';
 $('filename').textContent=file.name;$('filemeta').textContent=(file.size/1024).toFixed(1)+' Ko · '+result.encoding.toUpperCase()+(result.bom.length?' avec BOM':'')+' · '+state.newline;
 $('workspace').hidden=false;$('search').value='';$('rawText').value=result.content;$('preview').scrollTop=0;switchView(false);analyze();$('workspace').scrollIntoView({behavior:'smooth',block:'start'});toast(state.zones.length+' zone(s) détectée(s). Vérifiez les résultats avant export.');
 }catch(e){toast('Lecture impossible : '+e.message);console.error(e)}
}
function randomSalt(){const data=new Uint8Array(16);crypto.getRandomValues(data);return Array.from(data,x=>x.toString(16).padStart(2,'0')).join('')}
function showSalt(edit=false){if(!edit||!$('saltInput').value)$('saltInput').value=randomSalt();$('saltDialog').hidden=false;$('saltInput').focus()}
function saveSalt(){const v=$('saltInput').value.trim();if(!v){toast('Saisissez un sel non vide.');return}AnonymiseEngine.setSalt(v);$('saltDialog').hidden=true;$('saltStatus').textContent='Sel configuré';if(state.source)render();toast('Sel mis à jour : les remplacements déterministes sont recalculés. Conservez ce sel pour reproduire les mêmes résultats.')}
attachEvents();showSalt();
let deferredInstall;window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();deferredInstall=event;$('install').hidden=false});
$('install').onclick=async()=>{if(!deferredInstall)return;deferredInstall.prompt();await deferredInstall.userChoice;deferredInstall=null;$('install').hidden=true};
if('serviceWorker' in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('./sw.js',{scope:'./'}).catch(err=>console.warn('Service worker non disponible',err)));
