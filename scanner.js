import { scanContent } from './detector.js';

export function fullScan(content) {
  if (!content) return { risk: 'none', flags: [], message: null };
  return scanContent(content);
}

export { scanContent } from './detector.js';
export { normalize } from './detector.js';
