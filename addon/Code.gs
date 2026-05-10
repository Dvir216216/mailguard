/**
 * MailGuard Gmail Add-on
 * Entry points are wired up in appsscript.json
 */

var DEFAULT_THRESHOLD = 70;
var SUSPICIOUS_THRESHOLD = 40;
var URL_REGEX = /\bhttps?:\/\/[^\s<>"']+/gi;

/**
 * Triggered when the user opens a Gmail message.
 */
function onGmailMessage(event) {
  var loading = buildLoadingCard();

  try {
    var accessToken = event && event.gmail && event.gmail.accessToken;
    var messageId = event && event.gmail && event.gmail.messageId;
    if (!accessToken || !messageId) {
      return [buildErrorCard('Missing Gmail context — open a message to analyze.')];
    }
    GmailApp.setCurrentMessageAccessToken(accessToken);

    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      return [buildErrorCard('Could not load message.')];
    }

    var payload = buildPayloadFromMessage(message);
    var result = analyzeEmail(payload);

    if (result && result.__error) {
      return [buildErrorCard(result.__error)];
    }
    return [buildResultCard(result)];
  } catch (err) {
    console.warn('onGmailMessage failed: ' + err.message);
    return [buildErrorCard('Unexpected error: ' + err.message)];
  }
}

function onHomepage() {
  return buildLoadingCard('Open an email to analyze it.');
}

/**
 * Convert a GmailMessage into the payload schema the backend expects.
 */
function buildPayloadFromMessage(message) {
  var senderRaw = message.getFrom() || '';
  var senderEmail = extractEmail(senderRaw);
  var senderName = extractName(senderRaw);
  var replyToRaw = message.getReplyTo() || '';
  var replyToEmail = extractEmail(replyToRaw);
  var subject = message.getSubject() || '';
  var bodyText = message.getPlainBody() || '';

  var rawHeaders = message.getRawContent() || '';
  var authResults = extractHeader(rawHeaders, 'Authentication-Results');
  var firstReceived = extractFirstHeader(rawHeaders, 'Received');
  var senderIp = parseIpFromReceived(firstReceived);

  var spfResult = parseAuthField(authResults, 'spf');
  var dkimResult = parseAuthField(authResults, 'dkim');
  var dmarcResult = parseAuthField(authResults, 'dmarc');

  var urls = extractUrls(bodyText);

  var attachments = [];
  try {
    var atts = message.getAttachments({ includeAttachments: true, includeInlineImages: false });
    for (var i = 0; i < atts.length && i < 20; i++) {
      var a = atts[i];
      attachments.push({
        name: a.getName ? a.getName() : '',
        mimeType: a.getContentType ? a.getContentType() : '',
        size: a.getSize ? a.getSize() : 0
      });
    }
  } catch (e) {
    // No attachment access — skip silently
  }

  return {
    sender_email: senderEmail,
    sender_name: senderName,
    reply_to: replyToEmail,
    subject: subject,
    body_text: bodyText,
    urls: urls,
    attachments: attachments,
    headers: {
      sender_ip: senderIp,
      spf_result: spfResult,
      dkim_result: dkimResult,
      dmarc_result: dmarcResult
    }
  };
}

function extractEmail(raw) {
  if (!raw) return '';
  var m = raw.match(/<([^>]+)>/);
  if (m) return m[1].trim().toLowerCase();
  return raw.trim().toLowerCase();
}

function extractName(raw) {
  if (!raw) return '';
  var m = raw.match(/^([^<]+)</);
  if (m) return m[1].replace(/"/g, '').trim();
  return '';
}

function extractHeader(rawHeaders, name) {
  if (!rawHeaders) return '';
  var lines = rawHeaders.split(/\r?\n/);
  var collected = [];
  var capturing = false;
  var prefix = name.toLowerCase() + ':';
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line === '') break; // end of header section
    if (line.toLowerCase().indexOf(prefix) === 0) {
      capturing = true;
      collected.push(line.slice(prefix.length).trim());
    } else if (capturing && /^[ \t]/.test(line)) {
      collected.push(line.trim());
    } else {
      capturing = false;
    }
  }
  return collected.join(' ');
}

function extractFirstHeader(rawHeaders, name) {
  return extractHeader(rawHeaders, name);
}

function parseIpFromReceived(receivedLine) {
  if (!receivedLine) return '';
  var m = receivedLine.match(/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/);
  if (m) return m[1];
  var m6 = receivedLine.match(/\[([0-9a-f:]{2,})\]/i);
  if (m6) return m6[1];
  return '';
}

function parseAuthField(authResults, field) {
  if (!authResults) return '';
  var re = new RegExp('\\b' + field + '\\s*=\\s*([a-zA-Z]+)', 'i');
  var m = authResults.match(re);
  return m ? m[1].toLowerCase() : '';
}

function extractUrls(body) {
  if (!body) return [];
  var matches = body.match(URL_REGEX) || [];
  var seen = {};
  var out = [];
  for (var i = 0; i < matches.length && out.length < 50; i++) {
    var url = matches[i].replace(/[\)\]\.,;:!\?>"']+$/, '');
    if (!seen[url]) {
      seen[url] = true;
      out.push(url);
    }
  }
  return out;
}

function analyzeEmail(payload) {
  var props = PropertiesService.getScriptProperties();
  var backendUrl = props.getProperty('BACKEND_URL');
  var apiKey = props.getProperty('API_KEY');

  if (!backendUrl || !apiKey) {
    return { __error: 'Add-on not configured: set BACKEND_URL and API_KEY in script properties.' };
  }

  var url = backendUrl.replace(/\/$/, '') + '/analyze';

  var options = {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-API-Key': apiKey },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(url, options);
    var code = response.getResponseCode();
    var text = response.getContentText();
    if (code < 200 || code >= 300) {
      return { __error: 'Backend returned HTTP ' + code };
    }
    return JSON.parse(text);
  } catch (err) {
    return { __error: 'Network error: ' + err.message };
  }
}

function buildLoadingCard(message) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(message || 'Analyzing email...')
      )
    )
    .build();
  return card;
}

function buildErrorCard(detail) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard — error'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(String(detail || 'Unknown error'))
      )
    )
    .build();
}

function verdictLabel(score) {
  if (score >= getUserThreshold()) return '🚨 MALICIOUS';
  if (score >= SUSPICIOUS_THRESHOLD) return '⚠️ SUSPICIOUS';
  return '✅ SAFE';
}

function buildResultCard(result) {
  result = result || {};
  var score = typeof result.score === 'number' ? result.score : 0;
  var label = verdictLabel(score);

  var header = CardService.newCardHeader().setTitle('MailGuard').setSubtitle(label);

  var scoreSection = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText('<b>Score: ' + score + '/100</b><br>' + label)
  );

  var signalsSection = CardService.newCardSection().setHeader('Signals');
  var signals = Array.isArray(result.signals) ? result.signals : [];
  if (signals.length === 0) {
    signalsSection.addWidget(CardService.newTextParagraph().setText('No signals fired.'));
  } else {
    for (var i = 0; i < signals.length; i++) {
      var s = signals[i];
      signalsSection.addWidget(
        CardService.newKeyValue()
          .setTopLabel('+' + s.points)
          .setContent(String(s.name || ''))
      );
    }
  }

  var card = CardService.newCardBuilder().setHeader(header).addSection(scoreSection).addSection(signalsSection);

  if (result.reasoning) {
    var reasoningSection = CardService.newCardSection().setHeader('LLM reasoning');
    reasoningSection.addWidget(CardService.newTextParagraph().setText(String(result.reasoning)));
    card.addSection(reasoningSection);
  }

  if (result.primary_threat_type) {
    var typeSection = CardService.newCardSection().addWidget(
      CardService.newKeyValue().setTopLabel('Threat type').setContent(String(result.primary_threat_type))
    );
    card.addSection(typeSection);
  }

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('<i>Powered by MailGuard</i>')
    )
  );

  return card.build();
}

function getUserThreshold() {
  var props = PropertiesService.getUserProperties();
  var raw = props.getProperty('THRESHOLD');
  var n = parseInt(raw, 10);
  if (isNaN(n) || n < 60 || n > 80) return DEFAULT_THRESHOLD;
  return n;
}

function saveUserThreshold(value) {
  var n = parseInt(value, 10);
  if (isNaN(n) || n < 60 || n > 80) {
    throw new Error('Threshold must be between 60 and 80.');
  }
  PropertiesService.getUserProperties().setProperty('THRESHOLD', String(n));
  return { ok: true, threshold: n };
}


