import { randomUUID } from 'node:crypto';
import { appendFile, lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { containsLikelySecret } from './policy.mjs';

const MAX_BYTES = 4 * 1024 * 1024;

export class MemoryStore {
  constructor(directory) {
    if (!path.isAbsolute(directory)) throw new Error('记忆目录必须是绝对路径。');
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, 'memory.jsonl');
    this.events = [];
    this.queue = Promise.resolve();
  }

  async init() {
    await mkdir(this.directory, { recursive: true });
    if (path.relative(this.directory, await realpath(this.directory)) !== '') throw new Error('记忆目录不能通过符号链接跳到别处。');
    try {
      const info = await lstat(this.file);
      if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_BYTES) throw new Error('记忆文件类型或大小异常，已停止加载。');
      const text = await readFile(this.file, 'utf8');
      if (text && !text.endsWith('\n')) throw new Error('记忆文件尾部不完整；请保留原文件后人工检查。');
      this.events = text.split('\n').filter(Boolean).map(line => {
        const event = JSON.parse(line);
        if (!event || event.version !== 1 || typeof event.id !== 'string' || typeof event.time !== 'string'
            || !['remember', 'forget', 'audit'].includes(event.kind)) throw new Error('记忆文件包含不支持的记录。');
        if (event.kind === 'remember' && (typeof event.text !== 'string' || event.text.length > 1200
            || typeof event.scope !== 'string' || containsLikelySecret(event.text))) throw new Error('记忆内容异常，已停止加载。');
        if (event.kind === 'forget' && typeof event.target !== 'string') throw new Error('停用记忆记录异常。');
        return event;
      });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    return this;
  }

  append(data) {
    const operation = this.queue.then(async () => {
      // Re-check before every write; never truncate or overwrite a journal.
      if (path.relative(this.directory, await realpath(this.directory)) !== '') throw new Error('记忆目录已改变，停止写入。');
      let size = 0;
      try {
        const info = await lstat(this.file);
        if (info.isSymbolicLink() || !info.isFile()) throw new Error('记忆文件不是普通文件。');
        size = info.size;
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      const event = { ...data, version: 1, id: randomUUID(), time: new Date().toISOString() };
      if (data.kind === 'remember') {
        const active = this.list(data.scope);
        if (active.length >= 80 || active.reduce((sum, item) => sum + item.text.length, 0) + data.text.length > 12_000) {
          throw new Error('当前范围的记忆已达 80 条或 12000 字符；请先用 /forget 停用不需要的条目。');
        }
        // Global additions must fit every already-known project's combined budget.
        if (data.scope === '*') {
          const scopes = new Set(this.events.filter(item => item.kind === 'remember').map(item => item.scope));
          for (const scope of scopes) {
            const items = this.list(scope);
            if (items.length >= 80 || items.reduce((sum, item) => sum + item.text.length, 0) + data.text.length > 12_000) {
              throw new Error('这条全局记忆会超出某个项目的记忆预算；请先停用旧条目。');
            }
          }
        }
      }
      const line = `${JSON.stringify(event)}\n`;
      if (size + Buffer.byteLength(line) > MAX_BYTES) throw new Error('记忆记录已达 4 MB，已停止写入；不会自动清理旧记录。');
      await appendFile(this.file, line, { encoding: 'utf8', mode: 0o600 });
      this.events.push(event);
      return event;
    });
    this.queue = operation.catch(() => {});
    return operation;
  }

  list(scope) {
    const forgotten = new Set(this.events.filter(event => event.kind === 'forget').map(event => event.target));
    return this.events.filter(event => event.kind === 'remember' && !forgotten.has(event.id)
      && (event.scope === '*' || event.scope === scope));
  }

  async remember(text, scope) {
    if (typeof text !== 'string' || text.trim().length === 0 || text.length > 1200) throw new Error('一条记忆需要 1—1200 个字符。');
    if (containsLikelySecret(text)) throw new Error('内容疑似包含凭据；请去掉密码、token 或密钥后再保存。');
    return this.append({ kind: 'remember', text: text.trim(), scope });
  }

  async forget(id, scope) {
    const item = this.list(scope).find(event => event.id === id);
    if (!item) throw new Error('没有找到这个范围内的有效记忆，请使用完整 ID。');
    return this.append({ kind: 'forget', target: item.id });
  }

  audit(tool, outcome) {
    // Deliberately omit raw commands, arguments, file contents and explanations.
    return this.append({ kind: 'audit', tool: String(tool).slice(0, 160), outcome });
  }
}
