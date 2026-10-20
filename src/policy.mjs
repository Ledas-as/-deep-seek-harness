import { createHash } from 'node:crypto';
import path from 'node:path';

// Exact names only: an unknown MCP tool is never trusted by a name substring.
// Recursive content search can include credentials. It receives a human review.
const READ_TOOLS = new Set(['read', 'read_image', 'glob']);
const INTERNAL_TOOLS = new Set(['guard_plan', 'guard_memory_list', 'guard_memory_propose', 'guard_search']);
const INTERACTION_TOOLS = new Set(['ask_user_question']);
const SHELL_TOOLS = new Set(['bash', 'pwsh', 'bash_persistent', 'pwsh_persistent', 'terminal', 'run_code']);
const PATH_KEYS = new Set(['file_path', 'path', 'directory', 'workdir', 'cwd']);

export function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
}

export function fingerprint(name, args) {
  return createHash('sha256').update(`${name}\n${stableJson(args)}`).digest('hex');
}

export function sensitivePath(value) {
  const parts = String(value).replace(/\\/gu, '/').split('/');
  return parts.some(part => /^\.env/iu.test(part)
    || /\.(?:pem|key|pfx|p12|crt|cer)$/iu.test(part)
    || /^(?:id_rsa|id_ed25519|id_ecdsa|credentials|secrets?)(?:\..*)?$/iu.test(part)
    || /^(?:\.ssh|\.aws|\.azure)$/iu.test(part));
}

export function pathsIn(args) {
  const found = [];
  function walk(value, key = '') {
    if (Array.isArray(value)) { for (const item of value) walk(item, key); }
    else if (value && typeof value === 'object') { for (const [k, v] of Object.entries(value)) walk(v, k); }
    else if (PATH_KEYS.has(key) && typeof value === 'string') found.push(value);
  }
  walk(args);
  return [...new Set(found)];
}

export function classify(name, args) {
  if (pathsIn(args).some(sensitivePath)) {
    return { kind: 'deny', label: '受保护的敏感文件', reason: '参数涉及敏感文件；请去掉凭据、私钥或 .env 文件。' };
  }
  if (INTERNAL_TOOLS.has(name)) return { kind: 'internal', label: '插件自己的说明或记忆功能' };
  if (INTERACTION_TOOLS.has(name)) return { kind: 'interaction', label: '向用户询问信息' };
  if (READ_TOOLS.has(name)) return { kind: 'read', label: '查看或搜索文件' };
  if (SHELL_TOOLS.has(name) || /(?:shell|terminal|exec|run_code)/iu.test(name)) {
    return { kind: 'review', label: '运行命令或脚本', risk: '可以改变或删除文件、启动程序、访问网络；插件无法仅凭文字证明它只会查看。' };
  }
  if (/^(?:write|edit|str_replace_editor|apply_patch)$/u.test(name)) {
    return { kind: 'review', label: '创建或修改文件', risk: '可能覆盖已有内容，或移除文件中的一部分；需要核对具体目标。' };
  }
  return { kind: 'review', label: '调用需要核对的工具', risk: '该工具不在直接放行的查看工具名单里；可能修改文件、外部服务或设置。' };
}

export function resolvedPaths(args, cwd) {
  const api = /^[A-Za-z]:[\\/]/u.test(cwd ?? '') ? path.win32 : path;
  return pathsIn(args).map(value => api.isAbsolute(value) ? api.normalize(value) : cwd ? api.resolve(cwd, value) : `未能确定完整路径：${value}`);
}

export function containsLikelySecret(text) {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk-|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|password|passwd|token|secret|密码|口令|密钥)\s*[:=：]\s*\S+/iu.test(text);
}
