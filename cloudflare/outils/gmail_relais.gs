function doPost(e) {
  const result = (ok) => ContentService.createTextOutput(JSON.stringify({ok}))
    .setMimeType(ContentService.MimeType.JSON);
  let lock;
  try {
    if (!e || !e.postData || e.postData.contents.length > 12000) return result(false);
    const envelope = JSON.parse(e.postData.contents);
    const secret = PropertiesService.getScriptProperties().getProperty('AG_MAIL_SECRET');
    if (!secret || secret.length < 32 || typeof envelope.payload !== 'string' ||
        !/^[0-9a-f]{64}$/.test(envelope.signature)) return result(false);
    const bytes = Utilities.computeHmacSha256Signature(envelope.payload, secret, Utilities.Charset.UTF_8);
    const expected = bytes.map((b) => ('0' + (b & 255).toString(16)).slice(-2)).join('');
    let mismatch = 0;
    for (let i = 0; i < 64; i++) mismatch |= expected.charCodeAt(i) ^ envelope.signature.charCodeAt(i);
    if (mismatch) return result(false);
    const p = JSON.parse(envelope.payload);

    if (p && p.action==='status') {
      if (!Number.isInteger(p.timestamp) || Math.abs(Date.now()/1000-p.timestamp)>300 ||
          !/^[0-9a-f]{48}$/.test(p.id) || Object.keys(p).some(key=>!['action','timestamp','id'].includes(key))) return result(false);
      const expectedSender=PropertiesService.getScriptProperties().getProperty('AG_EXPECTED_SENDER');
      const sender=Gmail.Users.getProfile('me').emailAddress;
      const cleanup=ScriptApp.getProjectTriggers().some(trigger=>trigger.getHandlerFunction()==='nettoyerCopiesGmail');
      return result(Boolean(expectedSender && sender.toLowerCase()===expectedSender.toLowerCase() && cleanup));
    }
    if (!Number.isInteger(p.timestamp) || Math.abs(Date.now()/1000 - p.timestamp) > 300 ||
        typeof p.to !== 'string' || p.to.length > 254 ||
        !/^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(etu\.sorbonne-universite\.fr|sorbonne-universite\.fr)$/.test(p.to) ||
        !/^[0-9a-f]{48}$/.test(p.id) ||
        Object.keys(p).some(key => !['to', 'otp', 'timestamp', 'id'].includes(key)) ||
        typeof p.otp !== 'string' || !/^[0-9]{6}$/.test(p.otp)) return result(false);
    lock = LockService.getScriptLock();
    if (!lock.tryLock(10000)) return result(false);
    const cache = CacheService.getScriptCache();
    if (cache.get(p.id)) { essayerNettoyageGmail_('AG_CLEANUP_'+p.id); return result(true); }
    const sender = Gmail.Users.getProfile('me').emailAddress;
    const expectedSender=PropertiesService.getScriptProperties().getProperty('AG_EXPECTED_SENDER');
    if (expectedSender && sender.toLowerCase()!==expectedSender.toLowerCase()) return result(false);
    const messageId = '<ag-verification-'+p.id+'@agemocratie.fr>';
    const raw = [
      'From: '+sender, 'To: '+p.to, 'Message-ID: '+messageId,
      'X-AGemocratie-Verification: otp-v1', 'X-AGemocratie-Request: '+p.id,
      'Subject: =?UTF-8?B?'+Utilities.base64Encode('AGémocratie — vérification de votre adresse',Utilities.Charset.UTF_8)+'?=',
      'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64', '',
      Utilities.base64Encode('Votre code de vérification : '+p.otp+'\nValable 10 minutes. Ce code ne permet pas de voter. Ne le partagez pas.',Utilities.Charset.UTF_8)
    ].join('\r\n');
    const sent = Gmail.Users.Messages.send({raw:Utilities.base64EncodeWebSafe(raw,Utilities.Charset.UTF_8)},'me');
    cache.put(p.id, 'sent', 600);
    PropertiesService.getScriptProperties().setProperty('AG_CLEANUP_'+p.id,JSON.stringify({id:sent.id,messageId,requestId:p.id}));
    essayerNettoyageGmail_('AG_CLEANUP_'+p.id);
    return result(true);
  } catch (_) {
    return result(false);
  } finally {
    if (lock && lock.hasLock()) lock.releaseLock();
  }
}

function essayerNettoyageGmail_(key) {
  if (!/^AG_CLEANUP_[0-9a-f]{48}$/.test(key)) return false;
  const props=PropertiesService.getScriptProperties();
  const stored=props.getProperty(key);
  if (!stored) return true;
  try {
    const entry=JSON.parse(stored);
    if (!entry || !/^[a-zA-Z0-9]+$/.test(entry.id) || entry.messageId!=='<ag-verification-'+key.substring(11)+'@agemocratie.fr>') return false;
    const message=Gmail.Users.Messages.get('me',entry.id,{format:'metadata',metadataHeaders:['Message-ID','X-AGemocratie-Verification','X-AGemocratie-Request','From','To']});
    const h={};
    for (const item of message.payload.headers || []) h[item.name.toLowerCase()]=item.value;
    const sender=Gmail.Users.getProfile('me').emailAddress.toLowerCase();
    const from=(h.from || '').match(/(?:^|<)([^<>\s]+@[^<>\s]+)>?$/);
    if (!Array.isArray(message.labelIds) || !message.labelIds.includes('SENT') ||
        (entry.requestId && (entry.requestId!==key.substring(11) || h['x-agemocratie-request']!==entry.requestId)) ||
        h['x-agemocratie-verification']!=='otp-v1' || !from || from[1].toLowerCase()!==sender ||
        !/^[^@\s,<>]+@(etu\.sorbonne-universite\.fr|sorbonne-universite\.fr)$/.test((h.to || '').toLowerCase())) return false;
    Gmail.Users.Messages.remove('me',entry.id);
    props.deleteProperty(key);
    return true;
  } catch (_) { return false; }
}

function nettoyerCopiesGmail() {
  const lock=LockService.getScriptLock();
  if (!lock.tryLock(10000)) return;
  try {
    const props=PropertiesService.getScriptProperties().getProperties();
    Object.keys(props).filter(key=>/^AG_CLEANUP_[0-9a-f]{48}$/.test(key)).slice(0,50).forEach(essayerNettoyageGmail_);
  } finally { lock.releaseLock(); }
}

function installerNettoyageGmail() {
  Gmail.Users.getProfile('me');
  if (!ScriptApp.getProjectTriggers().some(trigger=>trigger.getHandlerFunction()==='nettoyerCopiesGmail'))
    ScriptApp.newTrigger('nettoyerCopiesGmail').timeBased().everyMinutes(1).create();
}
