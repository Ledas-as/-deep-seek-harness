import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { resolvedPaths, sensitivePath } from './policy.mjs';

export function within(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

// Resolve the nearest existing ancestor too: a new file can sit below a junction.
export async function canonicalPath(target) {
  try { return await realpath(target); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    try {
      if ((await lstat(target)).isSymbolicLink()) throw new Error('本地链接的实际目标不可解析。');
    } catch (entryError) { if (entryError.code !== 'ENOENT') throw entryError; }
    const parent = path.dirname(target);
    if (parent === target) throw error;
    return path.join(await canonicalPath(parent), path.basename(target));
  }
}

function protectedProjectPath(target, root) {
  return path.relative(root, target).split(path.sep).some(part =>
    /^(?:\.git|\.agents|\.codex|\.dsh|node_modules|AGENTS\.md)$/iu.test(part));
}

export async function projectTargets(args, cwd, protectedRoots = []) {
  const targets = resolvedPaths(args, cwd);
  if (targets.length === 0) return undefined;
  const root = await canonicalPath(cwd);
  const protectedPaths = await Promise.all(protectedRoots.map(canonicalPath));
  for (const target of targets) {
    // Avoid drive-relative, device and alternate-stream paths in the automatic lane.
    if (process.platform === 'win32' && (target.slice(2).includes(':') || target.startsWith('\\\\')
      || target.split(/[\\/]/u).some(part => /[. ]$/u.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part)))) return undefined;
    const actual = await canonicalPath(target);
    if (!within(target, cwd) || !within(actual, root) || sensitivePath(actual)
        || protectedProjectPath(actual, root) || protectedProjectPath(target, cwd)
        || protectedPaths.some(directory => within(actual, directory))) return undefined;
  }
  return targets;
}

// This is a small command grammar, not a blacklist that claims arbitrary scripts are safe.
// Project task scripts remain trusted workspace code and require a confining host executor.
export function routineCommand(command) {
  if (typeof command !== 'string' || command.length > 4000 || /[\r\n;&|<>`$%!^(){}]/u.test(command)) return false;
  const tokens = command.trim().match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+/gu) ?? [];
  if (tokens.join(' ') !== command.trim().replace(/ +/gu, ' ')) return false;
  const words = tokens.map(token => /^['"]/u.test(token) ? token.slice(1, -1) : token);
  const [binary, ...args] = words;
  const task = /^(?:test|lint|typecheck|build|check)$/u;
  if (/^(?:npm|pnpm)(?:\.cmd)?$/u.test(binary ?? '')) {
    return (args.length === 1 && args[0] === 'test') || (args.length === 2 && args[0] === 'run' && task.test(args[1]));
  }
  if (/^yarn(?:\.cmd)?$/u.test(binary ?? '')) return args.length === 1 && task.test(args[0]);
  if (/^node(?:\.exe)?$/u.test(binary ?? '')) {
    if (!['--test', '--check'].includes(args[0])) return false;
    if (args[0] === '--check' && args.length !== 2) return false;
    return args.slice(1).every(value => !value.startsWith('-') && /^[\w ./\\*-]+\.(?:mjs|cjs|js|ts)$/u.test(value)
      && !path.isAbsolute(value) && !/^[A-Za-z]:/u.test(value) && !value.split(/[\\/]/u).includes('..') && !sensitivePath(value));
  }
  if (/^git(?:\.exe)?$/u.test(binary ?? '')) {
    return args[0] === 'status' && args.slice(1).every(value => ['--short', '--porcelain', '--branch'].includes(value));
  }
  return false;
}

export async function assessRoutine(ctx, exec, cwd, protectedRoots) {
  const args = exec.arguments;
  if (args.sandbox_permissions !== undefined) return undefined;
  if (['write', 'edit'].includes(exec.name)
      || (exec.name === 'str_replace_editor' && ['create', 'str_replace', 'insert', 'view'].includes(args.command))) {
    if (typeof (args.file_path ?? args.path) !== 'string') return undefined;
    if (exec.name === 'write' && (typeof args.content !== 'string' || args.content.trim() === '')) return undefined;
    return await projectTargets(args, cwd, protectedRoots) ? 'project' : undefined;
  }
  if (exec.name === 'grep') {
    const targets = await projectTargets({ path: args.path ?? cwd }, cwd, protectedRoots);
    // Native grep includes hidden/ignored files. Broad searches use guard_search instead.
    if (targets?.length === 1 && (await lstat(targets[0])).isFile()) return 'project';
    return undefined;
  }
  if (!['bash', 'pwsh'].includes(exec.name) || !routineCommand(args.command)) return undefined;
  const shell = ctx.get?.('shell');
  const policy = ctx.get?.('sandboxPolicy')?.resolve({ session: exec.agent.session });
  if (!shell || shell.sandboxMode === undefined || !['read-only', 'workspace-write'].includes(policy?.mode)) return undefined;
  const targets = await projectTargets({ workdir: args.workdir ?? cwd }, cwd, protectedRoots);
  const root = await canonicalPath(cwd);
  if (!targets || !within(await canonicalPath(policy.workspaceRoot), root)) return undefined;
  if (!within(await canonicalPath(targets[0]), await canonicalPath(policy.workspaceRoot))) return undefined;
  return 'sandbox';
}

const TEXT_FILES = /\.(?:[cm]?js|[cm]?ts|tsx|jsx|json|md|txt|html|css|scss|ya?ml|toml|py|rs|go|java|cs|vue|svelte|xml|sql|sh|ps1)$/iu;
const SKIP_DIRS = /^(?:node_modules|vendor|dist|build|coverage|DSH-Memory-Guard)$/iu;

export async function searchProject(query, target, cwd, protectedRoots, signal) {
  if (typeof query !== 'string' || query.length < 1 || query.length > 500 || /[\r\n]/u.test(query)) throw new Error('请输入 1—500 字符的单行文字，使用字面量搜索。');
  const targets = await projectTargets({ path: target ?? cwd }, cwd, protectedRoots);
  if (!targets) throw new Error('搜索只允许当前项目中的普通文件位置。');
  const matches = [];
  const queue = [targets[0]];
  let files = 0;
  let bytes = 0;
  let limited = false;
  while (queue.length && matches.length < 200) {
    signal?.throwIfAborted();
    const current = queue.pop();
    const name = path.basename(current);
    if (sensitivePath(current) || (current !== targets[0] && (name.startsWith('.') || SKIP_DIRS.test(name)))) continue;
    const info = await lstat(current);
    if (info.isSymbolicLink()) continue;
    if (!await projectTargets({ path: current }, cwd, protectedRoots)) continue;
    if (info.isDirectory()) {
      if (queue.length > 5000) { limited = true; break; }
      const children = await readdir(current);
      queue.push(...children.slice(0, 5000).sort().reverse().map(child => path.join(current, child)));
      if (children.length > 5000) limited = true;
    } else if (info.isFile() && TEXT_FILES.test(name) && info.size <= 512 * 1024) {
      if (++files > 2000 || bytes + info.size > 8 * 1024 * 1024) { limited = true; break; }
      bytes += info.size;
      const text = await readFile(current, { encoding: 'utf8', signal });
      if (text.includes('\0')) continue;
      const lines = text.split('\n');
      for (let index = 0; index < lines.length && matches.length < 200; index++) {
        if (lines[index].includes(query)) matches.push(`${path.relative(cwd, current)}:${index + 1}: ${lines[index].slice(0, 400)}`);
      }
    }
  }
  return `${matches.length ? matches.join('\n') : '未找到匹配。'}\n\n已搜索 ${files} 个普通文本文件；跳过敏感文件、隐藏目录、依赖和生成目录。${limited || queue.length || matches.length === 200 ? '已达到搜索上限，请缩小目录继续。' : ''}`;
}
