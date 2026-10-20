import { defineTool } from '@deepseek-ai/dsh-tools';
import { install } from './plugin.mjs';

export const name = 'memory-guard';
export const inject = ['tools', 'systemPrompt', 'userQuestions', 'commands', 'workingDirectory'];
export const apply = async (ctx, config = {}) => {
  await install(ctx, config, defineTool);
};
