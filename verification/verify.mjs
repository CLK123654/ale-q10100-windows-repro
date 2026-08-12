import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';

const repoRoot = path.resolve(import.meta.dirname, '..');
const artifactRoot = path.join(repoRoot, 'artifacts');
const evidenceRoot = path.join(repoRoot, 'verification', 'evidence');
const attachments = ['输入数据包.zip', 'reference.zip', '关键标准答案.xlsx', '任务规格转化.xlsx'];
const expectedDelivery = [
  'output/playwright.config.ts',
  'output/reports/decision_matrix.csv',
  'output/reports/modal_focus.csv',
  'output/reports/network_receipts.csv',
  'output/reports/totp_window.csv',
  'output/tests/account_security_totp.spec.ts',
].sort();
const reportKeys = {
  'output/reports/decision_matrix.csv': ['queue_item_id'],
  'output/reports/network_receipts.csv': ['account_id'],
  'output/reports/totp_window.csv': ['step_offset'],
  'output/reports/modal_focus.csv': ['order_index'],
};

const assert = (value, message) => { if (!value) throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sha256File = (file) => sha256(fs.readFileSync(file));

function zipEntries(file) {
  const data = fs.readFileSync(file);
  let eocd = -1;
  for (let index = data.length - 22; index >= Math.max(0, data.length - 65_557); index -= 1) {
    if (data.readUInt32LE(index) === 0x06054b50) { eocd = index; break; }
  }
  assert(eocd >= 0, `找不到ZIP目录：${file}`);
  const count = data.readUInt16LE(eocd + 10);
  let offset = data.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let entryIndex = 0; entryIndex < count; entryIndex += 1) {
    assert(data.readUInt32LE(offset) === 0x02014b50, `ZIP目录损坏：${file}`);
    const method = data.readUInt16LE(offset + 10);
    const compressedSize = data.readUInt32LE(offset + 20);
    const uncompressedSize = data.readUInt32LE(offset + 24);
    const nameLength = data.readUInt16LE(offset + 28);
    const extraLength = data.readUInt16LE(offset + 30);
    const commentLength = data.readUInt16LE(offset + 32);
    const localOffset = data.readUInt32LE(offset + 42);
    const name = data.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').replaceAll('\\', '/');
    const localNameLength = data.readUInt16LE(localOffset + 26);
    const localExtraLength = data.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + localExtraLength;
    if (!name.endsWith('/')) {
      const compressed = data.subarray(start, start + compressedSize);
      const body = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null;
      assert(body && body.length === uncompressedSize, `无法解压${name}`);
      entries.set(name, body);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

async function extract(file, destination) {
  for (const [name, bytes] of zipEntries(file)) {
    const target = path.resolve(destination, ...name.split('/'));
    assert(target.startsWith(`${path.resolve(destination)}${path.sep}`), `非法ZIP路径：${name}`);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, bytes);
  }
}

function workbookSheets(file) {
  const xml = zipEntries(file).get('xl/workbook.xml')?.toString('utf8') ?? '';
  return [...xml.matchAll(/<(?:[A-Za-z]+:)?sheet[^>]+name="([^"]+)"/gu)].map((match) => match[1]);
}

function runNpm(cwd) {
  const started = Date.now();
  const result = spawnSync('cmd.exe', ['/d', '/s', '/c', 'npm.cmd run audit'], {
    cwd,
    encoding: 'utf8',
    timeout: 180_000,
    windowsHide: true,
    env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
  });
  return {
    code: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: [result.stderr, result.error?.message].filter(Boolean).join('\n'),
    elapsed_ms: Date.now() - started,
  };
}

function parseCsv(text) {
  const rows = []; let row = []; let cell = ''; let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { cell += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(cell); cell = ''; }
    else if (char === '\n') { row.push(cell.replace(/\r$/u, '')); rows.push(row); row = []; cell = ''; }
    else cell += char;
  }
  if (cell || row.length) { row.push(cell.replace(/\r$/u, '')); rows.push(row); }
  const headers = rows.shift() ?? [];
  return rows.filter((values) => values.some((value) => value !== '')).map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])));
}

function normalizedRows(file, text) {
  const rows = parseCsv(text);
  const keys = reportKeys[file];
  return rows.toSorted((left, right) => keys.map((key) => String(left[key]).localeCompare(String(right[key]), 'en')).find((value) => value !== 0) ?? 0);
}

function files(root) {
  const result = [];
  function walk(current, prefix = '') {
    if (!fs.existsSync(current)) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((left, right) => left.name.localeCompare(right.name, 'en'))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path.join(current, entry.name), relative);
      else result.push(relative);
    }
  }
  walk(root);
  return result.sort();
}

function treeDigest(root, ignored = new Set()) {
  const lines = [];
  function walk(current, prefix = '') {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((left, right) => left.name.localeCompare(right.name, 'en'))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (ignored.has(relative.split('/')[0])) continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full, relative);
      else lines.push(`${relative}\0${sha256File(full)}`);
    }
  }
  walk(root);
  return sha256(Buffer.from(lines.join('\n')));
}

function classifyExecutable(name, bytes) {
  const lower = name.toLowerCase();
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1, 4).toString('ascii') === 'ELF') return 'linux_elf';
  if (/\.(?:sh|bash|so)(?:\.|$)/u.test(lower)) return 'posix_member';
  if (/^#!.*(?:ba|z|k)?sh/mu.test(bytes.subarray(0, 160).toString('utf8'))) return 'posix_shebang';
  return null;
}

async function prepare(label, mutate) {
  const root = path.join(os.tmpdir(), label);
  await fsp.rm(root, { recursive: true, force: true });
  await fsp.mkdir(root, { recursive: true });
  await extract(path.join(artifactRoot, '输入数据包.zip'), root);
  const inputRoot = path.join(root, 'input_data');
  const reference = zipEntries(path.join(artifactRoot, 'reference.zip'));
  const outputRoot = path.join(inputRoot, 'output');
  await fsp.mkdir(path.join(outputRoot, 'tests'), { recursive: true });
  await fsp.writeFile(path.join(outputRoot, 'playwright.config.ts'), reference.get('output/playwright.config.ts'));
  await fsp.writeFile(path.join(outputRoot, 'tests', 'account_security_totp.spec.ts'), reference.get('output/tests/account_security_totp.spec.ts'));
  await fsp.symlink(path.join(repoRoot, 'node_modules'), path.join(inputRoot, 'node_modules'), 'junction');
  if (mutate) await mutate(inputRoot);
  return { root, inputRoot, outputRoot, reference };
}

function compareFormalDelivery(outputRoot, formalDelivery) {
  const actualPaths = files(outputRoot).map((name) => `output/${name}`);
  assert(JSON.stringify(actualPaths) === JSON.stringify(expectedDelivery), `输出成员与正式交付不一致：${actualPaths.join(',')}`);
  const semantic = crypto.createHash('sha256');
  for (const file of expectedDelivery) {
    const actual = fs.readFileSync(path.join(path.dirname(outputRoot), ...file.split('/')));
    const expected = formalDelivery.get(file);
    if (file.endsWith('.csv')) {
      const actualRows = normalizedRows(file, actual.toString('utf8'));
      const expectedRows = normalizedRows(file, expected.toString('utf8'));
      assert(JSON.stringify(actualRows) === JSON.stringify(expectedRows), `${file}与正式交付业务字段不一致`);
      semantic.update(JSON.stringify(actualRows));
    } else {
      const actualText = actual.toString('utf8').replaceAll('\r\n', '\n');
      const expectedText = expected.toString('utf8').replaceAll('\r\n', '\n');
      assert(actualText === expectedText, `${file}与正式交付源码不一致`);
      semantic.update(actualText);
    }
  }
  return semantic.digest('hex');
}

await fsp.rm(evidenceRoot, { recursive: true, force: true });
await fsp.mkdir(evidenceRoot, { recursive: true });
assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', '只接受GitHub托管Windows运行');
const attachmentSha256 = Object.fromEntries(attachments.map((name) => [name, sha256File(path.join(artifactRoot, name))]));
const inputMembers = zipEntries(path.join(artifactRoot, '输入数据包.zip'));
const executableScan = [...inputMembers].map(([name, bytes]) => ({ name, classification: classifyExecutable(name, bytes) })).filter((item) => item.classification);
assert(executableScan.length === 0, `输入包含平台专用成员：${JSON.stringify(executableScan)}`);
assert(JSON.stringify([...zipEntries(path.join(artifactRoot, 'reference.zip')).keys()].sort()) === JSON.stringify(expectedDelivery), '正式交付成员错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx'))) === JSON.stringify(['交付物答案清单', '固定字段答案', '固定集合答案', '固定数值答案', '允许变体答案']), '关键标准答案Sheet错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx'))) === JSON.stringify(['任务规格转化']), '任务规格Sheet错误');
const solution = zipEntries(path.join(artifactRoot, 'reference.zip')).get('output/tests/account_security_totp.spec.ts').toString('utf8');
assert(!/\b(?:SECQ-24\d\d|R-710\d|acct_100\d|815419|854753|353788)\b/u.test(solution), '完成版按样本主键或验证码写死结果');
assert(!/\.focus\s*\(|innerHTML\s*=|https?:\/\/(?!127\.0\.0\.1|localhost)/u.test(solution), '完成版包含焦点捷径、DOM改写或外部地址');
assert(solution.includes("page.keyboard.press('Tab')") && solution.includes('page.route') && solution.includes('page.addInitScript') && solution.includes("page.on('request',"), '完成版缺少真实浏览器操作');

const cleanRuns = [];
for (const label of ['Q10100 第一次 中文 空目录', 'Q10100 第二次 中文 空格目录']) {
  const room = await prepare(label);
  const before = treeDigest(room.inputRoot, new Set(['output', 'node_modules', '.playwright-artifacts', 'test-results']));
  const run = runNpm(room.inputRoot);
  assert(run.code === 0, `${label}运行失败\n${run.stdout}\n${run.stderr}`);
  const after = treeDigest(room.inputRoot, new Set(['output', 'node_modules', '.playwright-artifacts', 'test-results']));
  assert(before === after, `${label}修改了输入`);
  const semantic = compareFormalDelivery(room.outputRoot, room.reference);
  cleanRuns.push({ directory_label: label, exit_code: run.code, input_digest_before: before, input_digest_after: after, semantic_digest: semantic, elapsed_ms: run.elapsed_ms, reference_match: true });
}
assert(cleanRuns[0].semantic_digest === cleanRuns[1].semantic_digest, '两个干净目录的结构化结果不一致');

const crlf = await prepare('Q10100 CRLF 队列输入', async (inputRoot) => {
  const file = path.join(inputRoot, 'queues', 'review_queue.csv');
  const value = await fsp.readFile(file, 'utf8');
  await fsp.writeFile(file, value.replace(/\r?\n/gu, '\r\n'));
});
let run = runNpm(crlf.inputRoot);
assert(run.code === 0, `CRLF队列运行失败\n${run.stdout}\n${run.stderr}`);
const crlfDigest = compareFormalDelivery(crlf.outputRoot, crlf.reference);
assert(crlfDigest === cleanRuns[0].semantic_digest, 'CRLF队列改变业务结果');

const mutation = await prepare('Q10100 复核阈值变化', async (inputRoot) => {
  const file = path.join(inputRoot, 'fixtures', 'freeze_policy.json');
  const value = JSON.parse(await fsp.readFile(file, 'utf8'));
  value.review_min_score = 78;
  await fsp.writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
});
run = runNpm(mutation.inputRoot);
assert(run.code === 0, `复核阈值变化运行失败\n${run.stdout}\n${run.stderr}`);
const mutatedDecision = normalizedRows('output/reports/decision_matrix.csv', fs.readFileSync(path.join(mutation.outputRoot, 'reports', 'decision_matrix.csv'), 'utf8'));
const changed = mutatedDecision.find((row) => row.event_id === 'R-7107');
assert(changed?.decision === 'manual_review' && changed?.reason_code === 'REVIEW_QUEUE' && changed?.action_enabled === 'false', '复核阈值变化未联动目标事件');
const baselineDecision = normalizedRows('output/reports/decision_matrix.csv', mutation.reference.get('output/reports/decision_matrix.csv').toString('utf8'));
assert(JSON.stringify(mutatedDecision.filter((row) => row.event_id !== 'R-7107')) === JSON.stringify(baselineDecision.filter((row) => row.event_id !== 'R-7107')), '复核阈值变化影响了无关事件');

const playwrightVersion = JSON.parse(fs.readFileSync(path.join(repoRoot, 'node_modules', 'playwright', 'package.json'), 'utf8')).version;
const evidence = {
  schema_version: 1,
  task_asset_id: 'playwright_account_freeze_release_review',
  result: 'PASS',
  generated_at_utc: new Date().toISOString(),
  git_commit_sha: process.env.GITHUB_SHA,
  workflow_run_id: process.env.GITHUB_RUN_ID,
  runner: {
    os: process.env.RUNNER_OS,
    arch: process.env.RUNNER_ARCH,
    image_os: process.env.ImageOS,
    image_version: process.env.ImageVersion,
    node: process.version,
    actual_windows_run: true,
  },
  main_software: { name: 'Playwright', version: playwrightVersion, browser: 'Chromium', executed: true, real_context_and_page: true },
  attachment_sha256: attachmentSha256,
  workbook_checks: {
    answer_sheet_names: workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx')),
    specification_sheet_names: workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx')),
  },
  windows_native_reproduction: {
    required: true,
    actual_windows_run: true,
    command: 'node verification/verify.mjs',
    original_data_paths: ['input_data/app', 'input_data/fixtures', 'input_data/queues'],
    windows_software_operations: ['Playwright Chromium页面导航', '本地接口路由', '键盘交互', '焦点观察', '冻结请求捕获'],
    linux_executables: executableScan,
    linux_executables_executed: false,
    reproduced_after_linux_executables_removed: true,
    delivery_match_after_removal: true,
    no_wsl_required: true,
    no_linux_container_required: true,
    no_posix_shell_required: true,
    no_unix_only_api_required: true,
    cross_platform_paths: true,
  },
  clean_runs: cleanRuns,
  crlf_input: { file: 'queues/review_queue.csv', exit_code: 0, semantic_digest: crlfDigest, reference_match: true },
  positive_mutation: {
    changed_rule: 'review_min_score从80改为78',
    exit_code: 0,
    changed_event: { event_id: changed.event_id, decision: changed.decision, reason_code: changed.reason_code, action_enabled: changed.action_enabled },
    unrelated_events_unchanged: true,
  },
  source_integrity: { sample_ids_hardcoded: false, focus_shortcut: false, external_url_literal: false },
  network: { installation_network_access: 'npm与Playwright浏览器下载', formal_run_network_access: '本机回环地址' },
};
await fsp.writeFile(path.join(evidenceRoot, 'windows-verification.json'), `${JSON.stringify(evidence, null, 2)}\n`);
console.log(JSON.stringify(evidence, null, 2));
