const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const secret = crypto.randomBytes(48).toString('hex');
const sent = [], cache = new Map(), copies=new Map(), deleted=[], props=new Map([['AG_MAIL_SECRET',secret]]), triggers=[];
let fail = false, failDelete=false;
const context = {
  PropertiesService:{getScriptProperties:()=>({getProperty:key=>props.get(key),setProperty:(key,value)=>props.set(key,value),deleteProperty:key=>props.delete(key),getProperties:()=>Object.fromEntries(props)})},
  Utilities:{Charset:{UTF_8:'UTF-8'},computeHmacSha256Signature:(body,key)=>Array.from(crypto.createHmac('sha256',key).update(body).digest()),base64Encode:value=>Buffer.from(value).toString('base64'),base64EncodeWebSafe:value=>Buffer.from(value).toString('base64url')},
  ContentService:{MimeType:{JSON:'json'},createTextOutput:text=>({setMimeType:()=>JSON.parse(text)})},
  LockService:{getScriptLock:()=>({tryLock:()=>true,hasLock:()=>true,releaseLock:()=>{}})},
  CacheService:{getScriptCache:()=>({get:key=>cache.get(key),put:(key,value)=>cache.set(key,value)})},
  Gmail:{Users:{getProfile:()=>({emailAddress:'agemocratie@gmail.com'}),Messages:{
    send:({raw})=>{
      if(fail)throw Error('outage');
      const text=Buffer.from(raw,'base64url').toString('utf8');
      const [head,body]=text.split('\r\n\r\n');
      const headers=head.split('\r\n').map(line=>({name:line.slice(0,line.indexOf(':')),value:line.slice(line.indexOf(':')+1).trim()}));
      const id=crypto.randomBytes(8).toString('hex');
      headers.find(h=>h.name==='Message-ID').value='<rewritten-'+id+'@mail.gmail.com>';
      copies.set(id,{labelIds:['SENT'],payload:{headers}});
      sent.push({body:Buffer.from(body,'base64').toString('utf8'),headers});
      return {id};
    },
    get:(user,id)=>copies.get(id),
    remove:(user,id)=>{if(failDelete)throw Error('temporary outage');deleted.push(id);copies.delete(id);},
  }}},
  ScriptApp:{getProjectTriggers:()=>triggers,newTrigger:name=>({timeBased:()=>({everyMinutes:()=>({create:()=>triggers.push({getHandlerFunction:()=>name})})})})},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../outils/gmail_relais.gs'),'utf8'),context);
function request(overrides={},badSignature=false) {
  const payload = JSON.stringify({to:'test@etu.sorbonne-universite.fr',otp:'012345',timestamp:Math.floor(Date.now()/1000),id:crypto.randomBytes(24).toString('hex'),...overrides});
  const signature = badSignature?'0'.repeat(64):crypto.createHmac('sha256',secret).update(payload).digest('hex');
  return {postData:{contents:JSON.stringify({payload,signature})}};
}
const first=request();
assert.equal(context.doPost(first).ok,true);
assert.equal(context.doPost(first).ok,true);
assert.equal(sent.length,1); // Même requête rejouée : pas de deuxième mail.
assert.equal(copies.size,0);assert.equal(deleted.length,1);
assert.equal(context.doPost(request({},true)).ok,false);
assert.equal(context.doPost(request({to:'x@gmail.com'})).ok,false);
assert.equal(context.doPost(request({to:'x@sorbonne-universite.fr.evil'})).ok,false);
assert.equal(context.doPost(request({timestamp:0})).ok,false);
assert.equal(context.doPost(request({kind:'other'})).ok,false);
assert.equal(context.doPost(request({code:'123456789012'})).ok,false);
assert.equal(context.doPost(request({kind:'ag_code',code:'123456789012',to:'prof@sorbonne-universite.fr'})).ok,false);
assert.equal(context.doPost(request({otp:'123456789012'})).ok,false);
assert.equal(context.doPost(request({title:'Nom AG'})).ok,false);
assert.equal(context.doPost(request({to:'prof@sorbonne-universite.fr'})).ok,true);
assert.equal(sent.length,2);
assert.ok(!sent[1].body.includes('123456789012'));
assert.ok(sent[1].body.includes('012345'));
assert.ok(!sent[1].body.includes('AG de test'));
fail=true;
assert.equal(context.doPost(request()).ok,false);
fail=false;failDelete=true;
assert.equal(context.doPost(request()).ok,true); // Mail livré : ne pas invalider son OTP si le nettoyage est différé.
assert.equal(copies.size,1);
assert.equal([...props.keys()].filter(key=>key.startsWith('AG_CLEANUP_')).length,1);
failDelete=false;context.nettoyerCopiesGmail();assert.equal(copies.size,0);
assert.equal([...props.keys()].filter(key=>key.startsWith('AG_CLEANUP_')).length,0);
failDelete=true;
assert.equal(context.doPost(request()).ok,true);
const legacyKey=[...props.keys()].find(key=>key.startsWith('AG_CLEANUP_'));
const legacyEntry=JSON.parse(props.get(legacyKey));delete legacyEntry.requestId;
props.set(legacyKey,JSON.stringify(legacyEntry));
failDelete=false;context.nettoyerCopiesGmail();assert.equal(copies.size,0);
failDelete=true;assert.equal(context.doPost(request()).ok,true);
const nonceKey=[...props.keys()].find(key=>key.startsWith('AG_CLEANUP_'));
const nonceEntry=JSON.parse(props.get(nonceKey));
const nonceHeader=copies.get(nonceEntry.id).payload.headers.find(h=>h.name==='X-AGemocratie-Request');
const savedNonce=nonceHeader.value;nonceHeader.value='wrong';
failDelete=false;context.nettoyerCopiesGmail();assert.ok(copies.has(nonceEntry.id));
nonceHeader.value=savedNonce;context.nettoyerCopiesGmail();assert.equal(copies.size,0);
const other='abc123';copies.set(other,{payload:{headers:[{name:'Message-ID',value:'<unrelated@example.org>'}]}});
const wrongKey='AG_CLEANUP_'+'0'.repeat(48);
props.set(wrongKey,JSON.stringify({id:other,messageId:'<ag-verification-'+'0'.repeat(48)+'@agemocratie.fr>'}));
context.nettoyerCopiesGmail();assert.ok(copies.has(other)); // Aucun effacement d'un autre mail.
context.installerNettoyageGmail();context.installerNettoyageGmail();assert.equal(triggers.length,1);
function statusRequest(overrides={}) {
  const payload=JSON.stringify({action:'status',timestamp:Math.floor(Date.now()/1000),id:crypto.randomBytes(24).toString('hex'),...overrides});
  return {postData:{contents:JSON.stringify({payload,signature:crypto.createHmac('sha256',secret).update(payload).digest('hex')})}};
}
const sentBeforeStatus=sent.length;
assert.equal(context.doPost(statusRequest()).ok,false);
props.set('AG_EXPECTED_SENDER','agemocratie@gmail.com');
assert.equal(context.doPost(statusRequest()).ok,true);
assert.equal(context.doPost(statusRequest({timestamp:0})).ok,false);
assert.equal(context.doPost(statusRequest({to:'test@etu.sorbonne-universite.fr'})).ok,false);
assert.equal(sent.length,sentBeforeStatus);
assert.equal(context.doPost({postData:{contents:'bad json'}}).ok,false);
console.log('Relais Gmail : envoi, signatures, suppression ciblée, reprise et conservation des autres mails OK.');
