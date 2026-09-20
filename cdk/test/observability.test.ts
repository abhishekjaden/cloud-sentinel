/**
 * Observability assertions.
 *
 * An objective is only as good as the alarm that enforces it, and alarms fail
 * quietly: one pointed at a metric that nothing emits sits at OK forever, and
 * one with no action tells nobody. These tests pin that every objective in
 * docs/slos.md has an alarm, that every alarm notifies the alarm topic, that
 * every metric an alarm or the dashboard reads is one a deployed resource
 * actually emits, and that every function records traces.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { ALARM_TOPIC_NAME, FUNCTION_NAMES, METRIC_NAMESPACE } from '../lib/names';
import { ApiStack } from '../lib/stacks/api-stack';
import { DnsStack } from '../lib/stacks/dns-stack';
import { IngestionStack } from '../lib/stacks/ingestion-stack';
import { ObservabilityStack } from '../lib/stacks/observability-stack';
import { RemediationStack } from '../lib/stacks/remediation-stack';
import { TriageStack } from '../lib/stacks/triage-stack';

const audit = { env: env(ACCOUNTS.audit) };
// Synthesized with the app's own feature flags from cdk.json, as `cdk synth`
// does. Several change what these tests read: without them, partitions stay
// unresolved in metric dimensions and functions get no CDK-managed log group.
// Every stack is added before the first template is taken: synthesis freezes
// the app, and adding a stack afterwards fails.
const { context } = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'));
const app = new cdk.App({ context });
const stacks = {
  ingestion: new IngestionStack(app, 'TestIngestion', audit),
  remediation: new RemediationStack(app, 'TestRemediation', audit),
  observability: new ObservabilityStack(app, 'TestObservability', audit),
  triage: new TriageStack(app, 'TestTriage', audit),
  api: (() => {
    const dns = new DnsStack(app, 'TestDns', audit);
    return new ApiStack(app, 'TestApi', { ...audit, apiZone: dns.apiZone, apiCertificate: dns.apiCertificate });
  })(),
};
const ingestion = Template.fromStack(stacks.ingestion);
const remediation = Template.fromStack(stacks.remediation);
const observability = Template.fromStack(stacks.observability);
const triage = Template.fromStack(stacks.triage);
const api = Template.fromStack(stacks.api);

const LAMBDA_DIR = path.join(__dirname, '..', 'lambda');
const SLO_DOC = path.join(__dirname, '..', '..', 'docs', 'slos.md');

type Props = Record<string, any>;
const resources = (t: Template, type: string): Props[] =>
  Object.values(t.findResources(type)).map((r: any) => r.Properties ?? {});

const alarms = (t: Template) => resources(t, 'AWS::CloudWatch::Alarm');

// ---------------------------------------------------------------- tracing
describe('tracing', () => {
  const functions = [ingestion, remediation, triage]
    .flatMap((t) => resources(t, 'AWS::Lambda::Function'));

  test('every function records X-Ray traces', () => {
    expect(functions.length).toBe(Object.keys(FUNCTION_NAMES).length);
    for (const fn of functions) {
      expect(fn.TracingConfig).toEqual({ Mode: 'Active' });
    }
  });

  test('the remediation state machine records X-Ray traces', () => {
    // With the functions it invokes also traced, a remediation is one trace.
    const [machine] = resources(remediation, 'AWS::StepFunctions::StateMachine');
    expect(machine.TracingConfiguration).toEqual({ Enabled: true });
  });

  test('nothing invokes a function before its log group exists', () => {
    // CDK creates each function's log group after the function. Anything that
    // invokes the function in between makes Lambda create the group first, and
    // the deployment then fails because the name is taken — and keeps failing,
    // since the group Lambda created outlives the rollback. It matters whenever
    // a function is replaced, as renaming them did.
    const invokers = ['AWS::Lambda::EventSourceMapping', 'AWS::Events::Rule', 'AWS::StepFunctions::StateMachine'];
    let checked = 0;
    for (const t of [ingestion, remediation, triage]) {
      const all = t.toJSON().Resources as Record<string, any>;
      // A function's log group is named "/aws/lambda/" joined to a Ref to it.
      const logGroupOf = new Map<string, string>();
      for (const [id, r] of Object.entries(all)) {
        const parts = r.Properties?.LogGroupName?.['Fn::Join']?.[1] ?? [];
        if (r.Type === 'AWS::Logs::LogGroup' && parts[0] === '/aws/lambda/' && parts[1]?.Ref) {
          logGroupOf.set(parts[1].Ref, id);
        }
      }
      for (const [fnId, logGroupId] of logGroupOf) {
        for (const [id, r] of Object.entries(all)) {
          if (!invokers.includes(r.Type)) continue;
          const props = JSON.stringify(r.Properties);
          if (!props.includes(`{"Ref":"${fnId}"}`) && !props.includes(`"Fn::GetAtt":["${fnId}","Arn"]`)) continue;
          expect({ invoker: id, dependsOn: r.DependsOn ?? [] })
            .toEqual({ invoker: id, dependsOn: expect.arrayContaining([logGroupId]) });
          checked += 1;
        }
      }
    }
    // the stream mapping, the correlation schedule, the high-severity rule, the
    // state machine once for each of the two functions it invokes, and the
    // triage schedule
    expect(checked).toBe(6);
  });

  test('every function has the fixed name the alarms look it up by', () => {
    // A function created without one would get a generated name that no alarm
    // or dashboard in the observability stack could find.
    const names = functions.map((fn) => fn.FunctionName).sort();
    expect(names).toEqual(Object.values(FUNCTION_NAMES).sort());
  });
});

// ---------------------------------------------------------------- objectives
describe('objectives', () => {
  const pipelineAlarms = alarms(observability);
  const apiAlarms = alarms(api);
  const byName = (list: Props[]) => new Map(list.map((a) => [a.AlarmName as string, a]));

  test('every documented objective has an alarm, and every alarm is documented', () => {
    // docs/slos.md is where an operator learns what an alarm means and what
    // to do about it; an alarm missing from it arrives without instructions.
    const documented = [...new Set(fs.readFileSync(SLO_DOC, 'utf8')
      .match(/cloudsentinel-slo-[a-z]+(?:-[a-z]+)*/g) ?? [])].sort();
    const defined = [...pipelineAlarms, ...apiAlarms].map((a) => a.AlarmName).sort();
    expect(defined).toEqual(documented);
    expect(defined).toEqual([
      'cloudsentinel-slo-api-available',
      'cloudsentinel-slo-api-latency',
      'cloudsentinel-slo-approvals-decided',
      'cloudsentinel-slo-findings-fresh',
      'cloudsentinel-slo-findings-stored',
      'cloudsentinel-slo-incidents-current',
      'cloudsentinel-slo-remediation-runs',
    ]);
  });

  test('every pipeline alarm notifies the alarm topic when it fires and when it clears', () => {
    const [topicId] = Object.keys(observability.findResources('AWS::SNS::Topic'));
    expect(pipelineAlarms.length).toBeGreaterThan(0);
    for (const alarm of pipelineAlarms) {
      expect(alarm.AlarmActions).toEqual([{ Ref: topicId }]);
      expect(alarm.OKActions).toEqual([{ Ref: topicId }]);
    }
  });

  test('the API alarms notify the same topic, found by name', () => {
    const topicArn = `arn:aws:sns:us-east-1:${ACCOUNTS.audit}:${ALARM_TOPIC_NAME}`;
    expect(apiAlarms.length).toBe(2);
    for (const alarm of apiAlarms) {
      expect(alarm.AlarmActions).toEqual([topicArn]);
      expect(alarm.OKActions).toEqual([topicArn]);
    }
  });

  test('silence from the correlator is a breach; silence elsewhere is not', () => {
    // The correlator publishes a count only when a run completes, so a crashed
    // or unscheduled correlator produces no data at all. Treating that as
    // healthy — the tempting fix for an alarm that fires on first deploy —
    // would switch the check off without anything looking different.
    const missing = Object.fromEntries(
      [...byName(pipelineAlarms)].map(([name, a]) => [name, a.TreatMissingData]));
    expect(missing).toEqual({
      'cloudsentinel-slo-findings-stored': 'notBreaching',
      'cloudsentinel-slo-findings-fresh': 'notBreaching',
      'cloudsentinel-slo-incidents-current': 'breaching',
      'cloudsentinel-slo-remediation-runs': 'notBreaching',
      'cloudsentinel-slo-approvals-decided': 'notBreaching',
    });
  });

  test('remediation health is measured by errors, not by failed workflows', () => {
    // Rejecting an approval fails the workflow. An alarm on ExecutionsFailed
    // would fire on every rejection, and be ignored soon after.
    const remediationRuns = byName(pipelineAlarms).get('cloudsentinel-slo-remediation-runs')!;
    const read = JSON.stringify(remediationRuns.Metrics);
    expect(read).toContain('"Errors"');
    expect(read).not.toContain('ExecutionsFailed');
  });
});

// ------------------------------------------------ metrics that actually exist
/** A metric as namespace, name and dimensions, from an alarm or a dashboard. */
interface MetricRef { namespace: string; name: string; dims: Record<string, string>; where: string }

function alarmMetrics(t: Template): MetricRef[] {
  return alarms(t).flatMap((a) => {
    const where = a.AlarmName;
    const dimsOf = (d: any[] = []) => Object.fromEntries(d.map((x) => [x.Name, x.Value]));
    if (!a.Metrics) {
      return [{ namespace: a.Namespace, name: a.MetricName, dims: dimsOf(a.Dimensions), where }];
    }
    return a.Metrics.filter((m: any) => m.MetricStat).map((m: any) => ({
      namespace: m.MetricStat.Metric.Namespace,
      name: m.MetricStat.Metric.MetricName,
      dims: dimsOf(m.MetricStat.Metric.Dimensions),
      where,
    }));
  });
}

/**
 * The dashboard body is a Fn::Join. Its tokens — the region each widget reads
 * and the alarms the status widget lists — only ever sit inside JSON strings,
 * so a placeholder keeps the body parseable.
 */
function render(value: any): string {
  if (typeof value === 'string') return value;
  if (value['Fn::Join']) return value['Fn::Join'][1].map(render).join(value['Fn::Join'][0]);
  if (value['Fn::GetAtt']) return value['Fn::GetAtt'].join('.');
  if (value.Ref) return value.Ref;
  throw new Error(`unexpected token in dashboard body: ${JSON.stringify(value)}`);
}

function dashboardMetrics(t: Template): MetricRef[] {
  return resources(t, 'AWS::CloudWatch::Dashboard').flatMap((d) => {
    const body = JSON.parse(render(d.DashboardBody));
    return body.widgets.flatMap((w: any) => (w.properties.metrics ?? [])
      // Expression rows carry no metric of their own; they read the rows below.
      .filter((row: any[]) => typeof row[0] === 'string')
      .map((row: any[]) => {
        const fields = row.filter((x) => typeof x === 'string');
        const [namespace, name, ...pairs] = fields;
        const dims: Record<string, string> = {};
        for (let i = 0; i < pairs.length; i += 2) dims[pairs[i]] = pairs[i + 1];
        return { namespace, name, dims, where: w.properties.title };
      }));
  });
}

describe('every metric the objectives read is emitted by something deployed', () => {
  const both = [ingestion, remediation, triage];
  const deployed = {
    functions: new Set(both.flatMap((t) => resources(t, 'AWS::Lambda::Function').map((r) => r.FunctionName))),
    rules: new Set(both.flatMap((t) => resources(t, 'AWS::Events::Rule').map((r) => r.Name))),
    streams: new Set(resources(ingestion, 'AWS::Kinesis::Stream').map((r) => r.Name)),
    machines: resources(remediation, 'AWS::StepFunctions::StateMachine').map((r) => r.StateMachineName),
  };

  // Metrics the handlers publish themselves. Each must appear in the handler
  // that publishes it; the handler tests pin the other side of the contract.
  const handlerSource: Record<string, string> = {
    normalizer: fs.readFileSync(path.join(LAMBDA_DIR, 'normalizer', 'handler.py'), 'utf8'),
    correlator: fs.readFileSync(path.join(LAMBDA_DIR, 'correlator', 'handler.py'), 'utf8'),
    triage: fs.readFileSync(path.join(LAMBDA_DIR, 'triage', 'handler.py'), 'utf8'),
  };

  function check(m: MetricRef) {
    const context = `${m.namespace}/${m.name} in "${m.where}"`;
    switch (m.namespace) {
      case 'AWS/Lambda':
        expect({ context, ok: deployed.functions.has(m.dims.FunctionName) }).toEqual({ context, ok: true });
        break;
      case 'AWS/Events':
        expect({ context, ok: deployed.rules.has(m.dims.RuleName) }).toEqual({ context, ok: true });
        break;
      case 'AWS/Kinesis':
        expect({ context, ok: deployed.streams.has(m.dims.StreamName) }).toEqual({ context, ok: true });
        break;
      case 'AWS/States':
        expect({
          context,
          ok: deployed.machines.some((n) => m.dims.StateMachineArn.endsWith(`:stateMachine:${n}`)),
        }).toEqual({ context, ok: true });
        break;
      case METRIC_NAMESPACE: {
        const source = handlerSource[m.dims.Component] ?? '';
        expect({ context, ok: source.includes(`_COMPONENT = "${m.dims.Component}"`) && source.includes(m.name) })
          .toEqual({ context, ok: true });
        break;
      }
      default:
        throw new Error(`${context}: no check for this namespace; add one before relying on it`);
    }
  }

  test('alarm metrics', () => {
    const read = alarmMetrics(observability);
    expect(read.length).toBeGreaterThan(0);
    read.forEach(check);
  });

  test('dashboard metrics', () => {
    const read = dashboardMetrics(observability);
    expect(read.length).toBeGreaterThan(0);
    read.forEach(check);
  });
});
