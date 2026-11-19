const byId = id => document.getElementById(id);
const rooms = byId('rooms');
const roomTitle = byId('room-title');
const roomAvatar = byId('room-avatar');
const status = byId('thread-status');
const transcript = byId('transcript');
const messages = byId('messages');
const empty = byId('empty');
const notice = byId('notice');
const composer = byId('composer');
const sender = byId('sender');
const sample = byId('sample');
const body = byId('body');
const attachment = byId('attachment');
const activity = byId('activity');
const send = byId('send');
const clear = byId('clear');
const mode = byId('mode');

let currentRoom = '';
let ready = false;
let busy = false;
let examples = [];
let revision = null;
let maxAttachmentBytes = 8192;
let liveModel = null;
const drafts = new Map();
const pending = new Map();

async function request(path, options) {
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'request_failed');
  return result;
}

function element(tag, text, className) {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}

function roomName(name) {
  return name[0].toUpperCase() + name.slice(1);
}

function updateControls() {
  for (const control of [sender, sample, body, attachment, send]) {
    control.disabled = busy || !ready;
  }
  clear.disabled = busy || !ready || revision === null;
  for (const button of rooms.children) {
    button.setAttribute('aria-pressed', String(button.dataset.room === currentRoom));
    button.setAttribute('aria-disabled', String(busy));
  }
}

function render(view) {
  revision = view.revision ?? null;
  const warning = view.active_warning;
  const cited = new Set(warning?.supporting.map(ref => ref.observation_number));
  messages.replaceChildren();
  view.messages.forEach((message, index) => {
    const number = index + 1;
    const row = document.createElement('li');
    row.id = 'message-' + number;
    row.tabIndex = -1;
    row.className = 'message';
    row.classList.toggle('outgoing', message.author === 'You');
    row.classList.toggle('cited', cited.has(number));
    row.append(element('span', message.author, 'sender'));

    const bubble = element('div', '', 'bubble');
    for (const part of message.parts) {
      if (part.kind === 'text') bubble.append(element('p', part.text));
    }
    for (const file of message.attachments) {
      const label = element('p', 'Attachment · ' + file.filename, 'muted');
      if (file.preview_url) {
        const photo = document.createElement('img');
        photo.className = 'attachment-image';
        photo.alt = 'Image attachment: ' + file.filename;
        label.hidden = true;
        photo.addEventListener('error', () => {
          photo.remove();
          label.hidden = false;
        });
        photo.src = file.preview_url;
        bubble.append(photo);
      }
      bubble.append(label);
    }
    row.append(bubble);
    messages.append(row);
  });
  empty.hidden = view.messages.length > 0;
  empty.textContent = 'No messages yet. Write a message or attach a file to begin.';
  notice.hidden = !warning;
  notice.replaceChildren();
  status.textContent = warning ? 'Active warning' : 'No active warning';
  if (warning) {
    notice.append(element('strong', 'Possible scam'), element('p', warning.rationale));
    const links = element('div', '', 'references');
    for (const number of cited) {
      const link = element('a', 'Message ' + number);
      link.href = '#message-' + number;
      link.addEventListener('click', event => {
        event.preventDefault();
        const target = byId('message-' + number);
        target.scrollIntoView({block: 'center'});
        target.focus({preventScroll: true});
      });
      links.append(link);
    }
    notice.append(links);
  }
  transcript.scrollTop = transcript.scrollHeight;
}

function loadConversation() {
  return request('/api/conversations/' + currentRoom).then(render);
}

async function openRoom(name) {
  if (busy || (name === currentRoom && ready)) return;
  if (currentRoom) {
    drafts.set(currentRoom, {text: body.value, sender: sender.value, sample: sample.value});
  }
  currentRoom = name;
  const label = roomName(name);
  roomTitle.textContent = label;
  roomAvatar.textContent = label[0];
  roomAvatar.className = 'avatar ' + name;
  const draft = drafts.get(name);
  body.value = draft?.text ?? '';
  sender.value = draft?.sender ?? 'You';
  sample.value = draft?.sample ?? '';
  attachment.value = '';
  ready = false;
  busy = true;
  revision = null;
  updateControls();
  messages.replaceChildren();
  notice.hidden = true;
  notice.replaceChildren();
  empty.hidden = false;
  empty.textContent = 'Loading conversation…';
  status.textContent = 'Loading warning status…';
  activity.textContent = '';
  try {
    await loadConversation();
    ready = true;
  } catch {
    empty.textContent = 'Unable to load messages. Select this conversation to try again.';
    status.textContent = 'Warning status unavailable';
  } finally {
    busy = false;
    updateControls();
  }
}

const descriptions = {
  warn: 'Warning sent to the partner.',
  update: 'Warning updated with new evidence.',
  no_action: 'Message observed. No new warning.',
  unavailable: 'Message observed. Assessment unavailable in this demo.',
};

function sizeLabel(bytes) {
  return bytes >= 1048576 ? (bytes / 1048576) + ' MiB' : (bytes / 1024) + ' KiB';
}

function showQuota(quota) {
  if (liveModel) {
    mode.textContent = 'Gemini 3.1 Flash-Lite · Live' + (quota
      ? (quota.blocked ? ' · API paused' : ' · ' + Math.max(0, quota.limit - quota.used) + ' calls left today') : '');
  }
}

function encodeAttachment(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.slice(reader.result.indexOf(',') + 1));
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

sample.addEventListener('change', () => {
  if (!sample.value) return;
  body.value = examples[Number(sample.value)].body;
  sender.value = 'Demo contact';
  body.focus();
});
body.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    if (ready && !busy) composer.requestSubmit();
  }
});

composer.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !ready) return;
  const file = attachment.files[0];
  if (!body.value.trim() && !file) {
    activity.textContent = 'Write a message or attach a file before sending.';
    body.focus();
    return;
  }
  const refocus = [body, send].includes(document.activeElement);
  busy = true;
  updateControls();
  activity.textContent = 'Checking message…';
  try {
    if (file && file.size > maxAttachmentBytes) {
      activity.textContent = 'This file is over the ' + sizeLabel(maxAttachmentBytes) + ' limit.';
      return;
    }
    const payload = {author: sender.value, body: body.value};
    if (file) {
      payload.attachment = {id: 'file-1', filename: file.name, base64: await encodeAttachment(file)};
    }
    const identity = JSON.stringify(payload);
    if (pending.get(currentRoom)?.identity !== identity) {
      pending.set(currentRoom, {identity, id: crypto.randomUUID()});
    }
    const result = await request('/api/conversations/' + currentRoom + '/messages', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: pending.get(currentRoom).id, ...payload}),
    });
    showQuota(result.quota);
    pending.delete(currentRoom);
    body.value = sample.value = attachment.value = '';
    try {
      await loadConversation();
      if (result.warning.reason === 'outgoing_message') {
        activity.textContent = 'Message sent.';
      } else if (liveModel && result.warning.reason === 'insufficient_evidence') {
        activity.textContent = 'Message observed. There is not enough new evidence for a warning.';
      } else if (result.warning.reason === 'same_evidence') {
        activity.textContent = 'Message observed. The warning still cites the same evidence.';
      } else if (liveModel && result.warning.action === 'unavailable') {
        activity.textContent = result.quota?.blocked || result.quota?.used >= result.quota?.limit
          ? 'Message observed. Gemini is paused or the demo allowance is used up.'
          : 'Message observed. The engine did not return an assessment.';
      } else {
        activity.textContent = descriptions[result.warning.action];
      }
    } catch {
      activity.textContent = 'Message observed. Reload the page to see the current warning.';
    }
  } catch {
    activity.textContent = 'Could not confirm delivery. Check the message and try again.';
  } finally {
    busy = false;
    updateControls();
    if (refocus && document.activeElement === document.body) body.focus();
  }
});

clear.addEventListener('click', async () => {
  if (busy || !ready || revision === null) return;
  if (!window.confirm('Clear all local messages, attachments, and warnings in ' + roomName(currentRoom) + '?')) return;
  busy = true;
  updateControls();
  activity.textContent = 'Clearing conversation…';
  try {
    const view = await request('/api/conversations/' + currentRoom + '/clear', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({revision}),
    });
    pending.delete(currentRoom);
    drafts.delete(currentRoom);
    body.value = sample.value = attachment.value = '';
    render(view);
    activity.textContent = 'Conversation cleared.';
  } catch (error) {
    if (error.message === 'conversation_changed') {
      try {
        await loadConversation();
        activity.textContent = 'This conversation changed. Review it before clearing again.';
      } catch {
        activity.textContent = 'Could not reload the conversation. Refresh the page to try again.';
      }
    } else {
      activity.textContent = 'Could not confirm the clear. Reload the conversation to check.';
    }
  } finally {
    busy = false;
    updateControls();
    if (revision === null) body.focus();
  }
});

(async () => {
  try {
    const demo = await request('/api/demo');
    liveModel = demo.model ?? null;
    maxAttachmentBytes = demo.attachment_bytes ?? maxAttachmentBytes;
    byId('attachment-limit').textContent = 'Up to ' + sizeLabel(maxAttachmentBytes);
    byId('attachment-label').textContent = 'Attachment, up to ' + sizeLabel(maxAttachmentBytes);
    byId('live-data-note').hidden = !liveModel;
    clear.hidden = !demo.can_clear;
    if (liveModel) showQuota(demo.quota);
    else mode.textContent = 'Local demo · Sample assessments';
    examples = demo.examples;
    byId('sample-tool').hidden = !examples.length;
    examples.forEach((example, index) => sample.add(new Option(example.label, index)));
    for (const name of demo.conversations) {
      const label = roomName(name);
      const button = element('button', '', 'room');
      button.type = 'button';
      button.dataset.room = name;
      const avatar = element('span', label[0], 'avatar ' + name);
      avatar.setAttribute('aria-hidden', 'true');
      button.append(avatar, element('span', label));
      button.addEventListener('click', () => openRoom(name));
      rooms.append(button);
    }
    await openRoom(demo.conversations[0]);
  } catch {
    empty.textContent = 'The local demo API is unavailable. Reload the page to try again.';
    status.textContent = 'Warning status unavailable';
  }
})();
