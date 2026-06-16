// Central account + region config for CloudSentinel.
// Workload account ID is filled in after Account Factory creates it (Day 2/3).

export const ACCOUNTS = {
  management: '062345618950',
  audit:      '118821712739',  // Config aggregator / Security Hub admin
  logArchive: '605911095588',  // Centralized CloudTrail / log storage
  workload:   '',              // TODO: set after Account Factory provisions it
};

export const REGION = 'us-east-1';
export const SECONDARY_REGION = 'us-west-2';

export const env = (account: string) => ({ account, region: REGION });
