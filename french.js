/* French contextual + validated business identifier detection. Fully offline. */
(function(root){
'use strict';
const compact=s=>s.replace(/[\s.-]/g,'').toUpperCase();
function mod97(text){let n=0;for(const c of text){const digits=/[A-Z]/.test(c)?String(c.charCodeAt(0)-55):c;for(const d of digits)n=(n*10+Number(d))%97}return n}
function siren(value){const v=value.replace(/\s/g,'');if(!/^\d{9}$/.test(v))return false;let sum=0;for(let i=0;i<v.length;i++){let d=+v[v.length-1-i];if(i%2){d*=2;if(d>9)d-=9}sum+=d}return sum%10===0}
function siret(value){const v=value.replace(/\s/g,'');if(!/^\d{14}$/.test(v))return false;let sum=0;for(let i=0;i<v.length;i++){let d=+v[v.length-1-i];if(i%2){d*=2;if(d>9)d-=9}sum+=d}return sum%10===0 || (v.startsWith('356000000')&&[...v].reduce((a,c)=>a+Number(c),0)%5===0)}
function iban(value){const v=compact(value);if(!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(v))return false;return mod97(v.slice(4)+v.slice(0,4))===1}
function bic(value){return /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/.test(compact(value))}
function vatFR(value){const v=compact(value);if(!/^FR[A-Z0-9]{2}\d{9}$/.test(v))return false;const key=v.slice(2,4);if(!/^\d{2}$/.test(key))return true;return +key===(12+3*(Number(v.slice(4))%97))%97}
function detect(text){
 const found=[];function add(start,end,type,rule,confidence){if(end>start)found.push({start,end,type,locator:'regex:'+rule,confidence,origin:'linguistic'})}
 function scan(pattern,type,rule,check,group=0){pattern.lastIndex=0;for(const m of text.matchAll(pattern)){const value=m[group],offset=m.index+m[0].indexOf(value);if(!check||check(value))add(offset,offset+value.length,type,rule,'validated')}}
 scan(/\b(?:\d[ ]?){9}\b/g,'business','SIREN',siren);
 scan(/\b(?:\d[ ]?){14}\b/g,'business','SIRET',siret);
 scan(/\bFR\s?[0-9A-Z]{2}\s?(?:\d[ ]?){9}\b/gi,'business','TVA_FR',vatFR);
 scan(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/gi,'bank','IBAN',iban);
 scan(/\b[A-Z]{4}[ ]?[A-Z]{2}[ ]?[A-Z0-9]{2}(?:[ ]?[A-Z0-9]{3})?\b/g,'bank','BIC',v=>bic(v)&&!/^IBAN/i.test(v));
 const labelled=[
  {regex:/\b(?:raison\s+sociale|dénomination\s+sociale|société|entreprise)\s*[:：=-]\s*([^\r\n;,]{3,100})/gi,type:'business',rule:'RAISON_SOCIALE'},
  {regex:/\b(?:prénom|prenom|first\s*name)\s*[:：=-]\s*([A-ZÀ-ÖØ-Ý][\p{L}' -]{1,60})/giu,type:'personal',rule:'PRENOM'},
  {regex:/\b(?:nom(?:\s+de\s+famille)?|last\s*name)\s*[:：=-]\s*([A-ZÀ-ÖØ-Ý][\p{L}' -]{1,60})/giu,type:'personal',rule:'NOM'},
  {regex:/\b(?:adresse|domicilié(?:e)?\s+au?|résidant\s+au?)\s*[:：=-]?\s*(\d{1,4}\s+(?:bis\s+|ter\s+)?(?:rue|avenue|av\.|boulevard|bd|place|chemin|allée|impasse|route|quai)\s+[\p{L}\d' -]{2,90})/giu,type:'personal',rule:'ADRESSE'},
  {regex:/\b(?:né(?:e)?\s+le|date\s+de\s+naissance)\s*[:：=-]?\s*(\d{1,2}[/. -]\d{1,2}[/. -]\d{4})/gi,type:'personal',rule:'NAISSANCE'},
  {regex:/\b(?:code\s+banque|code\s+guichet|RUM|référence\s+unique\s+de\s+mandat)\s*[:：=-]\s*([A-Z0-9][A-Z0-9 /._-]{2,50})/gi,type:'bank',rule:'BANQUE_RUM'},
  {regex:/\b(?:SIREN|SIRET|TVA\s*(?:intracommunautaire)?)\s*[:：=-]\s*([A-Z0-9 ]{9,22})/gi,type:'business',rule:'IDENTIFIANT_LABEL'},
 ];
 for(const spec of labelled){for(const m of text.matchAll(spec.regex)){let v=m[1].trimEnd();const pos=m.index+m[0].indexOf(m[1]);add(pos,pos+v.length,spec.type,spec.rule,'contextual')}}
 const titles=/\b(?:M\.|Mme|Madame|Monsieur|Dr|Docteur|Me)\s+([\p{Lu}][\p{L}'’-]{1,35}(?:\s+[\p{Lu}][\p{L}'’-]{1,35}){0,2})/gu;
 for(const m of text.matchAll(titles)){const v=m[1],p=m.index+m[0].lastIndexOf(v);add(p,p+v.length,'personal','PERSONNE_CIVILITE','contextual')}
 const address=/\b\d{1,4}\s+(?:bis\s+|ter\s+)?(?:rue|avenue|boulevard|place|chemin|allée|impasse|route|quai)\s+[\p{L}' -]{3,70}/giu;
 for(const m of text.matchAll(address))add(m.index,m.index+m[0].length,'personal','ADRESSE_FR','contextual');
 return found;
}
const api={detect,siren,siret,iban,bic,vatFR,mod97};
if(typeof module!=='undefined'&&module.exports)module.exports=api;root.AnonymiseFrench=api;
})(typeof globalThis!=='undefined'?globalThis:this);
