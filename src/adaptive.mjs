import { projectTargets } from './routine.mjs';

// This catches explicit risky effects, not every possible spelling of a script.
// All other non-routine tools still need the host's active Auto reviewer.
const RISKY_TOOL = /(?:^|_)(?:delete|remove|unlink|rmdir|trash|recycle|clean|prune|uninstall|kill|terminate|shutdown|reboot|commit|push|publish|deploy|release)(?:_|$)/iu;
const RISKY_COMMAND = /(?:^|[\s;|&("'`])(?:Remove-Item|Clear-RecycleBin|Clear-Content|Move-Item|Rename-Item|Stop-Process|Stop-Service|Restart-Computer|Stop-Computer|Set-Acl|Set-ExecutionPolicy|rm|rmdir|rd|del|erase|taskkill|shutdown|sudo|reg(?:\.exe)?)(?=[\s("']|$)|\bgit\s+(?:clean|reset|prune|gc|rebase|commit|push)\b|\b(?:npm|pnpm|yarn)\s+(?:uninstall|remove|publish)\b|\b(?:npm|pnpm)\s+(?:install|add)\b[^\r\n]*(?:--global|\s-g\b)|\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:clean|prune|deploy|release)\b|\b(?:pip|winget|choco|scoop)\s+(?:install|uninstall|remove)\b|\b(?:rmSync|unlinkSync|rmdirSync|rmtree)\s*\(|\.(?:rm|unlink|rmdir|remove)\s*\(|\b(?:File|Directory)\]\s*::\s*(?:Delete|Move)\s*\(/iu;
const EDITORS = new Set(['write', 'edit', 'str_replace_editor']);

export async function extraReview(exec, cwd, protectedRoots) {
  const args = exec.arguments;
  if (RISKY_TOOL.test(exec.name)) return '该操作可能删除、清理、发布或改变正在运行的程序。';
  if (args.sandbox_permissions !== undefined) return '该操作请求改变执行权限。';
  if (['command', 'script', 'code'].some(key => typeof args[key] === 'string' && RISKY_COMMAND.test(args[key]))) {
    return '命令含有删除、清理、移动、系统修改或发布操作。';
  }
  if (typeof args.patch === 'string' && /^\*\*\* (?:Delete File|Move to):/mu.test(args.patch)) {
    return '补丁含有文件删除或移动。';
  }
  if (EDITORS.has(exec.name)) {
    if (exec.name === 'str_replace_editor' && args.command === 'view') return undefined;
    if (exec.name === 'str_replace_editor' && !['create', 'str_replace', 'insert'].includes(args.command)) {
      return '编辑操作的影响需要核对。';
    }
    if (exec.name === 'write' && (typeof args.content !== 'string' || !args.content.trim())) {
      return '该操作可能清空整个文件。';
    }
    if (!await projectTargets(args, cwd, protectedRoots)) return '修改位置超出普通项目文件范围，或无法核对。';
  }
  return undefined;
}

export function hostAutoActive(ctx, agent) {
  try {
    const service = ctx.get?.('permissionPresets');
    return service?.names?.includes('auto') === true && service.current(agent.session) === 'auto';
  } catch { return false; }
}

export function hostFullAccessActive(ctx, agent) {
  try {
    const service = ctx.get?.('permissionPresets');
    // Never infer full access from approval=never: Auto children use it too.
    return service?.names?.includes('danger-full-access') === true
      && service.current(agent.session) === 'danger-full-access';
  } catch { return false; }
}
