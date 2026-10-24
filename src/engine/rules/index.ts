import type { Rule } from '../types';
import { adminWildcard } from './admin-wildcard';
import { conditionSanity } from './condition-sanity';
import { crossAccountTrust } from './cross-account-trust';
import { dataExfilActions } from './data-exfil-actions';
import { missingMfaCondition } from './missing-mfa-condition';
import { missingSecureTransport } from './missing-secure-transport';
import { notActionAllow } from './not-action-allow';
import { policyVersion } from './policy-version';
import { privilegeEscalation } from './privilege-escalation';
import { publicPrincipal } from './public-principal';
import { resourceWildcardOnMutatingAction } from './resource-wildcard-on-mutating-action';
import { serviceWildcard } from './service-wildcard';
import { unknownAction } from './unknown-action';

export const RULES: readonly Rule[] = [
  adminWildcard,
  serviceWildcard,
  privilegeEscalation,
  publicPrincipal,
  notActionAllow,
  resourceWildcardOnMutatingAction,
  dataExfilActions,
  crossAccountTrust,
  missingMfaCondition,
  missingSecureTransport,
  conditionSanity,
  unknownAction,
  policyVersion,
];

export function getRule(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}
