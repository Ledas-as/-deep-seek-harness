import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, mkdir, appendFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { classify, fingerprint, resolvedPaths, sensitivePath } from '../src/policy.mjs';
import { MemoryStore } from '../src/store.mjs';
import { install } from '../src/plugin.mjs';
import { routineCommand } from '../src/routine.mjs';

// These fixtures are append-only. No real shell command or deletion is executed.
async function fixture(options = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-guard-test-'));
  const listeners = new Map();
  const guards = [];
  const definitions = new Map();
  const commands = new Map();
  const sections = [];
  const disposers = [];
  const questions = [];
  let answer = 'allow';
  let cwd = root;
  let sandbox = options.sandbox;
  let confines = options.confines ?? true;
  const ctx = {
    get: name => name === 'shell' ? { sandboxMode: confines ? 'workspace-write' : undefined }
      : name === 'sandboxPolicy' ? { resolve: () => ({ mode: sandbox, workspaceRoot: options.sandboxRoot ?? cwd }) } : undefined,
    tools: { register: tool => { definitions.set(tool.name, tool); return () => definitions.delete(tool.name); },
      get: name => definitions.get(name), guard: guard => guards.push(guard) },
    systemPrompt: { section: section => sections.push(section) },
    commands: { register: command => commands.set(command.name, command) },
    workingDirectory: { get: () => cwd },
    effect: callback => disposers.push(callback()),
    on: (name, listener) => {
      if (!listeners.has(name)) listeners.set(name, []);
      listeners.get(name).push(listener);
    },
    userQuestions: { ask: async request => {
      questions.push(request.questions[0]);
      if (typeof answer === 'function') return answer(request);
      if (answer === 'throw') throw new Error('No UI');
      const { id } = request.questions[0];
      return { answers: [{ id, selected: [answer === 'allow' ? '仅允许这一次' : '拒绝执行'] }] };
    } },
  };
  definitions.set('pwsh', { name: 'pwsh' });
  definitions.set('write', { name: 'write' });
  definitions.set('unknown_mcp_delete', { name: 'unknown_mcp_delete' });
  definitions.set('read', { name: 'read' });
  definitions.set('run_code', { name: 'run_code' });
  const state = await install(ctx, { dataDir: path.join(root, 'memory'),
    ...(options.defaultMode ? {} : { mode: options.mode ?? 'strict' }) }, value => value);
  const agent = { session: {} };
  const makeExec = (name, args, owner = agent) => ({ name, arguments: args, agent: owner,
    token: Symbol('exec'), signal: new AbortController().signal, callId: 'test' });
  const pre = async exec => {
    const list = listeners.get('tools/pre-execute') ?? [];
    const dispatch = i => i === list.length ? { kind: 'allow' } : list[i](exec, () => dispatch(i + 1));
    return dispatch(0);
  };
  const final = exec => guards.map(guard => guard(exec)).find(reason => reason !== undefined);
  const run = async exec => {
    const decision = await pre(exec);
    if (decision.kind === 'allow') {
      const reason = final(exec);
      if (reason) return { kind: 'deny', reason };
    }
    for (const listener of listeners.get('tools/result') ?? []) listener(exec, {});
    return decision;
  };
  ctx.tools.execute = async input => {
    const exec = { ...makeExec(input.name, input.arguments, input.agent), signal: input.signal };
    const decision = await run(exec);
    if (decision.kind !== 'allow') return { isError: true, content: [{ type: 'text', text: decision.reason }] };
    const value = await definitions.get(input.name).execute(exec.arguments, exec);
    return { isError: false, content: [{ type: 'text', text: value }] };
  };
  const plan = async (name, args, owner = agent) => definitions.get('guard_plan').execute({
    tool_name: name, arguments_json: JSON.stringify(args), summary: '修改指定的测试文件',
    reason: '完成用户指定的测试任务', impact: '可能改变文件现有内容，需要核对目标',
  }, makeExec('guard_plan', {}, owner));
  return { root, state, ctx, agent, commands, definitions, sections, questions, makeExec, pre, final, run, plan,
    setAnswer: value => { answer = value; }, setCwd: value => { cwd = value; },
    setSandbox: value => { sandbox = value; }, setConfinement: value => { confines = value; },
    dispose: () => disposers.forEach(callback => callback()) };
}

test('only a small exact-name list is trusted; scripts and MCP stay reviewable', () => {
  assert.equal(classify('read', { file_path: 'notes.txt' }).kind, 'read');
  assert.equal(classify('ask_user_question', {}).kind, 'interaction');
  for (const name of ['pwsh', 'bash', 'run_code', 'grep', 'mcp_read_delete', 'write', 'edit', 'job_kill']) {
    assert.equal(classify(name, {}).kind, 'review', name);
  }
});

test('sensitive filenames are denied, including Windows paths', () => {
  for (const name of ['.env', '.env.local', 'C:\\a\\id_rsa', 'C:\\a\\cert.pem', '/a/.ssh/config']) {
    assert.equal(sensitivePath(name), true, name);
    assert.equal(classify('read', { file_path: name }).kind, 'deny');
  }
  assert.equal(sensitivePath('notes.txt'), false);
});

test('fingerprints ignore object key order but bind all arguments and tool name', () => {
  assert.equal(fingerprint('pwsh', { a: 1, b: 2 }), fingerprint('pwsh', { b: 2, a: 1 }));
  assert.notEqual(fingerprint('pwsh', { a: 1 }), fingerprint('pwsh', { a: 2 }));
  assert.notEqual(fingerprint('pwsh', {}), fingerprint('bash', {}));
  assert.deepEqual(resolvedPaths({ file_path: '../b.txt' }, 'C:\\work\\a'), ['C:\\work\\b.txt']);
});

test('ordinary file reading passes without a human question', async () => {
  const f = await fixture();
  assert.equal((await f.run(f.makeExec('read', { file_path: path.join(f.root, 'notes.txt') }))).kind, 'allow');
  assert.equal(f.questions.length, 0);
});

test('sensitive reads stop before a question and cannot pass the final guard', async () => {
  const f = await fixture();
  const exec = f.makeExec('read', { file_path: path.join(f.root, '.env.local') });
  assert.equal((await f.pre(exec)).kind, 'deny');
  assert.ok(f.final(exec));
  assert.equal(f.questions.length, 0);
});

test('scripts require a registered explanation even if described as read-only', async () => {
  const f = await fixture();
  assert.equal((await f.run(f.makeExec('pwsh', { command: 'Get-Date', description: '只是查看时间' }))).kind, 'deny');
  assert.equal(f.questions.length, 0);
});

test('one human answer permits exactly one call with a Chinese review and no raw code', async () => {
  const f = await fixture();
  const args = { command: 'never-executed-test-command', description: '调整测试文件内容' };
  await f.plan('pwsh', args);
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'allow');
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  assert.equal(f.questions.length, 1);
  assert.match(f.questions[0].detail, /\*\*操作\*\*：修改指定的测试文件/u);
  assert.match(f.questions[0].detail, /命令可能改动或删除文件/u);
  assert.ok(!f.questions[0].detail.includes(args.command));
  const detail = await f.commands.get('guard-detail').handler({ agent: f.agent });
  assert.ok(detail.text.includes(args.command));
});

test('changing arguments or current directory invalidates a plan', async () => {
  const f = await fixture();
  const args = { command: 'a', description: '修改测试内容' };
  await f.plan('pwsh', args);
  assert.equal((await f.run(f.makeExec('pwsh', { ...args, command: 'b' }))).kind, 'deny');
  f.setCwd(path.join(f.root, 'other'));
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
});

test('a plan cannot authorize a different session', async () => {
  const f = await fixture();
  const args = { command: 'a' };
  await f.plan('pwsh', args);
  assert.equal((await f.run(f.makeExec('pwsh', args, { session: {} }))).kind, 'deny');
});

for (const answer of ['deny', 'throw']) {
  test(`rejected or unavailable human confirmation fails closed: ${answer}`, async () => {
    const f = await fixture();
    f.setAnswer(answer);
    await f.plan('write', { file_path: path.join(f.root, 'notes.txt'), content: 'test' });
    assert.equal((await f.run(f.makeExec('write', { file_path: path.join(f.root, 'notes.txt'), content: 'test' }))).kind, 'deny');
  });
}

test('custom input and mismatched answers never count as approval', async () => {
  const f = await fixture();
  f.setAnswer(request => ({ answers: [{ id: request.questions[0].id, selected: ['仅允许这一次'], custom: '改一下' }] }));
  await f.plan('pwsh', { command: 'a' });
  assert.equal((await f.run(f.makeExec('pwsh', { command: 'a' }))).kind, 'deny');
  f.setAnswer(() => ({ answers: [{ id: 'wrong-id', selected: ['仅允许这一次'] }] }));
  await f.plan('pwsh', { command: 'b' });
  assert.equal((await f.run(f.makeExec('pwsh', { command: 'b' }))).kind, 'deny');
});

test('a later allow result cannot bypass the final monotonic guard', async () => {
  const f = await fixture();
  const exec = f.makeExec('unknown_mcp_delete', { path: 'notes.txt' });
  assert.equal((await f.pre(exec)).kind, 'deny');
  assert.ok(f.final(exec));
});

test('a skipped pre-execute chain does not grant access even to read tools', async () => {
  const f = await fixture();
  assert.ok(f.final(f.makeExec('read', { file_path: 'notes.txt' })));
});

test('approval tokens are one-use and attached to the execution identity', async () => {
  const f = await fixture();
  const args = { command: 'a' };
  await f.plan('pwsh', args);
  const exec = f.makeExec('pwsh', args);
  assert.equal((await f.pre(exec)).kind, 'allow');
  assert.ok(f.final(f.makeExec('pwsh', args)));
  assert.equal(f.final(exec), undefined);
  assert.ok(f.final(exec));
});

test('reloading or cancellation during confirmation revokes the pending operation', async () => {
  const f = await fixture();
  f.setAnswer(request => {
    f.dispose();
    return { answers: [{ id: request.questions[0].id, selected: ['仅允许这一次'] }] };
  });
  await f.plan('pwsh', { command: 'a' });
  assert.equal((await f.run(f.makeExec('pwsh', { command: 'a' }))).kind, 'deny');
});

test('model plugin management is denied and PTC cannot bypass review', async () => {
  const f = await fixture();
  assert.equal((await f.run(f.makeExec('plugin_manager', { action: 'remove' }))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('run_code', { code: 'tools.write({})' }))).kind, 'deny');
});

test('models cannot replace a plugin-owned tool under a trusted name', async () => {
  const f = await fixture();
  f.definitions.set('guard_memory_list', { name: 'guard_memory_list' });
  assert.equal((await f.run(f.makeExec('guard_memory_list', {}))).kind, 'deny');
});

test('memory uses explicit confirmation, scoped recall and append-only forgetting', async () => {
  const f = await fixture();
  const tool = f.definitions.get('guard_memory_propose');
  f.setAnswer('deny');
  await tool.execute({ text: '请用中文说明操作', scope: 'project' }, f.makeExec('guard_memory_propose', {}));
  assert.equal(f.state.store.list(f.root.toLowerCase()).length, 0);
  f.setAnswer('allow');
  await tool.execute({ text: '请用中文说明操作', scope: 'project' }, f.makeExec('guard_memory_propose', {}));
  const projectScope = process.platform === 'win32' ? f.root.toLowerCase() : f.root;
  const item = f.state.store.list(projectScope)[0];
  assert.equal(item.text, '请用中文说明操作');
  assert.equal(f.state.store.list('another-project').length, 0);
  const before = await readFile(f.state.store.file, 'utf8');
  await f.commands.get('forget').handler({ agent: f.agent, rawInput: item.id });
  const after = await readFile(f.state.store.file, 'utf8');
  assert.ok(after.startsWith(before));
  assert.equal(f.state.store.list(projectScope).length, 0);
  const reopened = await new MemoryStore(f.state.store.directory).init();
  assert.equal(reopened.list(projectScope).length, 0);
});

test('human commands preserve explicit global memory across sessions', async () => {
  const f = await fixture();
  const result = await f.commands.get('remember').handler({ agent: f.agent, rawInput: ' global 使用简单中文' });
  assert.equal(result.kind, 'success');
  assert.equal(f.commands.get('remember').recordInput, false);
  const reopened = await new MemoryStore(f.state.store.directory).init();
  assert.equal(reopened.list('another-project')[0].text, '使用简单中文');
  const section = f.sections.find(item => item.name === 'memory-guard:rules');
  assert.match(section.text, /不要只发命令/u);
  assert.equal(section.interpolate, false);
});

test('secrets are rejected before a memory question or journal append', async () => {
  const f = await fixture();
  await assert.rejects(f.definitions.get('guard_memory_propose').execute({ text: 'token=not-a-real-token', scope: 'global' }, f.makeExec('guard_memory_propose', {})));
  assert.equal(f.questions.length, 0);
  const result = await f.commands.get('remember').handler({ agent: f.agent, rawInput: '密码：测试值' });
  assert.equal(result.kind, 'error');
  assert.equal(f.state.store.events.length, 0);
});

test('audit records exclude raw code, arguments and file contents', async () => {
  const f = await fixture();
  const args = { command: 'never-store-this-command' };
  await f.plan('pwsh', args);
  await f.run(f.makeExec('pwsh', args));
  const journal = await readFile(f.state.store.file, 'utf8');
  assert.ok(!journal.includes(args.command));
  assert.match(journal, /human-approved/u);
});

test('invalid memory journals fail visibly instead of silently discarding history', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-guard-corrupt-'));
  await mkdir(path.join(root, 'memory'));
  await appendFile(path.join(root, 'memory', 'memory.jsonl'), '{broken');
  await assert.rejects(new MemoryStore(path.join(root, 'memory')).init(), /不完整/u);
});

test('symbolic links into sensitive names are denied without reading their contents', async t => {
  const f = await fixture();
  const target = path.join(f.root, 'credentials');
  await mkdir(target);
  const link = path.join(f.root, 'notes-link');
  try { await symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (error.code === 'EPERM') return t.skip('Windows 未授权创建 symlink'); throw error; }
  assert.equal((await f.run(f.makeExec('read', { file_path: link }))).kind, 'deny');
});

test('expired plans cannot be reused', async () => {
  const f = await fixture();
  const realNow = Date.now;
  try {
    const now = realNow();
    Date.now = () => now;
    await f.plan('pwsh', { command: 'a' });
    Date.now = () => now + 6 * 60_000;
    assert.equal((await f.run(f.makeExec('pwsh', { command: 'a' }))).kind, 'deny');
  } finally { Date.now = realNow; }
});

test('explanations reject English-only text and code dumps', async () => {
  const f = await fixture();
  const tool = f.definitions.get('guard_plan');
  const base = { tool_name: 'pwsh', arguments_json: '{"command":"a"}', summary: '更改测试内容', reason: '验证测试行为', impact: '修改测试文件内容' };
  await assert.rejects(tool.execute({ ...base, summary: 'execute command' }, f.makeExec('guard_plan', {})));
  await assert.rejects(tool.execute({ ...base, summary: '执行 `Remove-Item` 命令' }, f.makeExec('guard_plan', {})));
  assert.equal((await f.run(f.makeExec('pwsh', { command: 'a' }))).kind, 'deny');
});

test('cancellation before or during human review blocks dispatch', async () => {
  const f = await fixture();
  const controller = new AbortController();
  await f.plan('pwsh', { command: 'a' });
  const exec = { ...f.makeExec('pwsh', { command: 'a' }), signal: controller.signal };
  f.setAnswer(request => {
    controller.abort();
    return { answers: [{ id: request.questions[0].id, selected: ['仅允许这一次'] }] };
  });
  assert.equal((await f.run(exec)).kind, 'deny');
  assert.ok(f.final(exec));
});

test('memory byte budget is checked inside the serialized append queue', async () => {
  const f = await fixture();
  const scope = 'test-project';
  const results = await Promise.allSettled(Array.from({ length: 11 }, () => f.state.store.remember('测'.repeat(1200), scope)));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 10);
  assert.equal(results.filter(result => result.status === 'rejected').length, 1);
  assert.equal(f.state.store.list(scope).length, 10);
});

test('live self-check verifies a real denial and unregisters its harmless probe', async () => {
  const f = await fixture();
  const size = f.definitions.size;
  const result = await f.commands.get('guard-check').handler({ agent: f.agent });
  assert.equal(result.kind, 'success');
  assert.match(result.text, /执行体运行 0 次/u);
  assert.equal(f.definitions.size, size);
  assert.equal(f.questions.length, 0);
  assert.equal(f.state.store.events.length, 0);
});

test('live self-check does not report success for an allowed call', async () => {
  const f = await fixture();
  const size = f.definitions.size;
  f.ctx.tools.execute = async () => ({ isError: false, content: [] });
  const result = await f.commands.get('guard-check').handler({ agent: f.agent });
  assert.equal(result.kind, 'error');
  assert.match(result.text, /自检未通过/u);
  assert.equal(f.definitions.size, size);
});

test('commands that require arguments advertise an input hint to the native UI', async () => {
  const f = await fixture();
  assert.match(f.commands.get('remember').input.hint, /记忆内容/u);
  assert.match(f.commands.get('forget').input.hint, /记忆 ID/u);
  assert.equal(f.commands.get('guard-check').input, undefined);
});

test('balanced is the default; routine project writes and edits need no plan or question', async () => {
  const f = await fixture({ defaultMode: true });
  for (const [name, args] of [
    ['write', { file_path: path.join(f.root, 'notes.txt'), content: '普通内容' }],
    ['edit', { file_path: path.join(f.root, 'notes.txt'), old_string: 'a', new_string: 'b' }],
    ['str_replace_editor', { command: 'create', path: path.join(f.root, 'new.txt'), file_text: '内容' }],
  ]) assert.equal((await f.run(f.makeExec(name, args))).kind, 'allow', name);
  assert.equal(f.questions.length, 0);
  const status = await f.commands.get('guard').handler({ agent: f.agent });
  assert.match(status.text, /日常模式/u);
  assert.match(f.sections.find(section => section.name === 'memory-guard:rules').text, /不要每调用一个工具/u);
});

test('automatic project changes never grant calls outside the project or to protected paths', async () => {
  const f = await fixture({ mode: 'balanced' });
  for (const target of [path.join(f.root, '..', 'outside.txt'), path.join(f.root, '.git', 'config'),
    path.join(f.root, '.agents', 'rules.md'), path.join(f.root, 'AGENTS.md'),
    path.join(f.root, 'node_modules', 'package', 'index.js'), path.join(f.root, '.env'),
    path.join(f.root, 'memory', 'memory.jsonl')]) {
    assert.equal((await f.run(f.makeExec('write', { file_path: target, content: '内容' }))).kind, 'deny', target);
  }
  assert.equal((await f.run(f.makeExec('write', { file_path: path.join(f.root, 'notes.txt'), content: '' }))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('write', { content: '没有路径' }))).kind, 'deny');
  assert.equal(f.questions.length, 0);
});

test('new files under junctions cannot escape the project or enter protected directories', async t => {
  const f = await fixture({ mode: 'balanced' });
  const outside = await mkdtemp(path.join(tmpdir(), 'dsh-guard-outside-'));
  const link = path.join(f.root, 'linked');
  try { await symlink(outside, link, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (error.code === 'EPERM') return t.skip('Windows 未授权创建 symlink'); throw error; }
  assert.equal((await f.run(f.makeExec('write', { file_path: path.join(link, 'new', 'file.txt'), content: '内容' }))).kind, 'deny');
  const protectedLink = path.join(f.root, 'memory-link');
  await symlink(path.join(f.root, 'memory'), protectedLink, process.platform === 'win32' ? 'junction' : 'dir');
  assert.equal((await f.run(f.makeExec('write', { file_path: path.join(protectedLink, 'new.txt'), content: '内容' }))).kind, 'deny');
});

test('only simple task commands qualify for the sandbox lane', () => {
  for (const command of ['npm test', 'npm run build', 'pnpm run typecheck', 'yarn lint',
    'node --test', 'node --test test/guard.test.mjs', 'node --check src/index.mjs', 'git status --short']) {
    assert.equal(routineCommand(command), true, command);
  }
  for (const command of ['npm install', 'npm run clean', 'npm run deploy', 'npm test; Remove-Item a',
    'npm test && rm -rf a', 'node -e "a"', 'node --test --import ./evil.js', 'node --test ../outside.js',
    'npm test\nrm a', '& npm test', 'git push', 'git clean -fd', 'pwsh -Command test', 'npm test > a',
    '$(npm test)', 'node --test "test/$(bad).js"']) assert.equal(routineCommand(command), false, command);
});

test('routine shell commands need actual confinement and the current workspace boundary', async () => {
  const f = await fixture({ mode: 'balanced', sandbox: 'workspace-write' });
  const args = { command: 'npm run build', description: '构建当前项目并检查编译结果' };
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'allow');
  assert.equal(f.questions.length, 0);
  f.setSandbox('danger-full-access');
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  f.setSandbox('workspace-write');
  f.setConfinement(false);
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  f.setConfinement(true);
  assert.equal((await f.run(f.makeExec('pwsh', { ...args, workdir: path.dirname(f.root) }))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('pwsh', { ...args, sandbox_permissions: 'danger-full-access' }))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('pwsh_persistent', args))).kind, 'deny');
  const wrongRoot = await fixture({ mode: 'balanced', sandbox: 'workspace-write', sandboxRoot: path.dirname(f.root) });
  assert.equal((await wrongRoot.run(wrongRoot.makeExec('pwsh', args))).kind, 'deny');
});

test('destructive and unknown tools still need a bound single-use review in balanced mode', async () => {
  const f = await fixture({ mode: 'balanced', sandbox: 'workspace-write' });
  const args = { command: 'Remove-Item sample.txt', description: '删除专用测试文件' };
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  await f.plan('pwsh', args);
  f.setAnswer('deny');
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  await f.plan('pwsh', args);
  f.setAnswer('allow');
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'allow');
  assert.equal((await f.run(f.makeExec('pwsh', args))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('mcp_read_delete', {}))).kind, 'deny');
  assert.equal((await f.run(f.makeExec('apply_patch', { patch: '*** Delete File: sample.txt' }))).kind, 'deny');
  assert.equal(f.questions.length, 2);
});

test('project search skips hidden and generated files and preserves native grep review for directories', async () => {
  const f = await fixture({ mode: 'balanced' });
  await mkdir(path.join(f.root, 'src'));
  await mkdir(path.join(f.root, '.cache'));
  await mkdir(path.join(f.root, 'node_modules'));
  await appendFile(path.join(f.root, 'src', 'example.js'), 'const marker = true;\n');
  await appendFile(path.join(f.root, '.cache', 'hidden.txt'), 'marker hidden');
  await appendFile(path.join(f.root, 'node_modules', 'dependency.js'), 'marker dependency');
  const search = f.definitions.get('guard_search');
  const exec = f.makeExec('guard_search', { query: 'marker' });
  assert.equal((await f.run(exec)).kind, 'allow');
  const result = await search.execute(exec.arguments, exec);
  assert.match(result, /example\.js:1:/u);
  assert.ok(!result.includes('marker hidden'));
  assert.ok(!result.includes('marker dependency'));
  assert.equal((await f.run(f.makeExec('grep', { pattern: 'marker', path: path.join(f.root, 'src', 'example.js') }))).kind, 'allow');
  const denied = await f.run(f.makeExec('grep', { pattern: 'marker', path: f.root }));
  assert.equal(denied.kind, 'deny');
  assert.match(denied.reason, /guard_search/u);
  await assert.rejects(search.execute({ query: 'marker', path: path.dirname(f.root) }, exec), /当前项目/u);
  assert.equal(f.questions.length, 0);
});

test('project search is literal, bounded, and cancellable', async () => {
  const f = await fixture({ mode: 'balanced' });
  await appendFile(path.join(f.root, 'many.txt'), 'a.*b\n'.repeat(250));
  const search = f.definitions.get('guard_search');
  const exec = f.makeExec('guard_search', {});
  const result = await search.execute({ query: 'a.*b' }, exec);
  assert.equal(result.split('\n').filter(line => line.includes('many.txt:')).length, 200);
  assert.match(result, /上限/u);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(search.execute({ query: 'a' }, { ...exec, signal: controller.signal }));
});

test('automatic calls still pass other host policies and cannot skip the final guard', async () => {
  const f = await fixture({ mode: 'balanced' });
  const exec = f.makeExec('write', { file_path: path.join(f.root, 'notes.txt'), content: '内容' });
  assert.ok(f.final(exec));
  f.ctx.on('tools/pre-execute', async () => ({ kind: 'deny', reason: '宿主仍然拒绝' }));
  assert.equal((await f.run(exec)).kind, 'deny');
  assert.equal((await f.commands.get('guard-check').handler({ agent: f.agent })).kind, 'success');
});

test('final guard revokes automatic permits after argument, cwd or confinement changes', async () => {
  const f = await fixture({ mode: 'balanced', sandbox: 'workspace-write' });
  const changedArgs = f.makeExec('write', { file_path: path.join(f.root, 'notes.txt'), content: '内容' });
  assert.equal((await f.pre(changedArgs)).kind, 'allow');
  changedArgs.arguments.file_path = path.join(f.root, '..', 'elsewhere.txt');
  assert.ok(f.final(changedArgs));
  const changedCwd = f.makeExec('write', { file_path: 'notes.txt', content: '内容' });
  assert.equal((await f.pre(changedCwd)).kind, 'allow');
  f.setCwd(path.dirname(f.root));
  assert.ok(f.final(changedCwd));
  f.setCwd(f.root);
  const changedSandbox = f.makeExec('pwsh', { command: 'npm test', description: '运行当前项目测试' });
  assert.equal((await f.pre(changedSandbox)).kind, 'allow');
  f.setSandbox('danger-full-access');
  assert.ok(f.final(changedSandbox));
});
