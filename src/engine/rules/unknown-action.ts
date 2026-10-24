import { SERVICE_PREFIXES } from '../data/service-prefixes';
import { isFullWildcard, splitAction } from '../matching';
import type { Rule } from '../types';
import { DOCS, describeTarget, makeFinding } from './helpers';

export const unknownAction: Rule = {
  id: 'unknown-action',
  severity: 'low',
  title: 'Unrecognised action',
  explanation:
    'IAM does not validate action names when you save a policy. A typo such as `s3:GetObjects` or an unknown service prefix is accepted and then silently never matches, so the permission you think you granted (or denied) does not exist.',
  remediation:
    'Check the spelling against the Service Authorization Reference. Action names are `prefix:Name`, where the prefix is the service namespace (for example `s3`, `dynamodb`, `elasticloadbalancing`).',
  references: [DOCS.actionsList],
  check({ policy }) {
    return policy.statements.flatMap((s) => {
      const list = s.actions.length > 0 ? s.actions : s.notActions;
      const element = s.actions.length > 0 ? 'Action' : 'NotAction';
      return list.flatMap((action) => {
        if (isFullWildcard(action)) return [];
        const parts = splitAction(action);
        if (!parts) {
          return [
            makeFinding(unknownAction, {
              statement: s,
              element,
              key: action.toLowerCase(),
              message: `${describeTarget(s)} lists "${action}", which is not in the form "service:Action".`,
            }),
          ];
        }
        if (parts.service.includes('*') || SERVICE_PREFIXES.has(parts.service)) return [];
        return [
          makeFinding(unknownAction, {
            statement: s,
            element,
            key: action.toLowerCase(),
            message: `${describeTarget(s)} lists "${action}" — "${parts.service}" is not a known service prefix.`,
          }),
        ];
      });
    });
  },
};
