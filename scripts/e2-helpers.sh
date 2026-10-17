#!/usr/bin/env bash
# E2, matched re-run: the normalizer denied its table, with the first run's
# workload and timeline, under the final configuration (ADR 0007's hour of
# retries, ADR 0008's rejection of unreadable records, and the alarm topic
# admitting CloudWatch). The expected signals are in docs/chaos-experiments.md,
# E2, "Matched re-run"; they were written before this script is run.
#
# Source it from the repository root, with the venv active and the audit
# profile logged in:
#
#   source .venv/Scripts/activate            # or .venv/bin/activate
#   aws sso login --profile cs-audit
#   source scripts/e2-helpers.sh
#
#   e2chk       preflight: identity, the role, an empty queue, three alarms OK,
#               no flood findings left from an earlier run
#   e2run       the run, about 41 minutes with the laptop awake: the denial;
#               200 findings at 20/s at +108 s; the denial removed at +942 s
#               (15 min 42 s, as on 7 October); then it waits for the held
#               findings to store and the alarms to settle. Ctrl-C removes the
#               denial before it returns. Everything printed also goes to
#               ~/Downloads/e2-matched-<UTC stamp>.txt
#   e2abort     remove the denial now (what Ctrl-C runs)
#   e2collect   the evidence after the run — the three alarms' histories, the
#               control-change log, the normalizer's metrics minute by minute,
#               the queue depth and the flood count — to
#               ~/Downloads/e2-matched-<UTC stamp>-evidence.txt
#   e2cleanup   purge the queue and remove the flood findings, incidents and
#               notes. Only after e2collect: the purge removes evidence
#   e2count     flood findings stored so far
#   e2depth     messages in the failure queue
#   e2wait N S  wait until the flood count reaches N, or S seconds pass
#   normlat     normal-traffic latency since the E1 re-run's rollback, to
#               docs/evaluation-normal.json and ~/Downloads/normal-latency.txt
#
# Times printed by this script are the sender's clock, which runs 12 to 21
# seconds ahead of AWS's; the record uses AWS's clocks (alarm histories, log
# timestamps, stream arrival stamps), which e2collect gathers.

E2_PROFILE="${E2_PROFILE:-cs-audit}"
E2_REGION="${E2_REGION:-us-east-1}"
E2_FUNCTION="CloudSentinel-Normalizer"
E2_QUEUE_NAME="cloudsentinel-failed-findings"
E2_POLICY_NAME="chaos-deny-write"
E2_ALARMS=(cloudsentinel-slo-findings-stored cloudsentinel-slo-findings-fresh cloudsentinel-slo-controls-unchanged)
E2_LOG_GROUP="/cloudsentinel/control-changes"
E2_COUNT=200
E2_RATE=20
E2_FLOOD_AT=108      # seconds after the denial, as on 7 October (19:05:41 → 19:07:29)
E2_DELETE_AT=942     # seconds after the denial, as on 7 October (19:05:41 → 19:21:23)
E2_DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"dynamodb:PutItem","Resource":"*"}]}'

e2_aws() { aws --profile "$E2_PROFILE" --region "$E2_REGION" "$@"; }

e2_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

e2_say() {
  local line
  line="$(e2_now) sender  $*"
  echo "$line"
  [ -n "$E2_LOG" ] && echo "$line" >> "$E2_LOG"
}

e2_role() {
  if [ -z "$E2_ROLE" ]; then
    E2_ROLE=$(e2_aws lambda get-function-configuration --function-name "$E2_FUNCTION" \
      --query Role --output text | sed 's#.*/##')
  fi
  [ -n "$E2_ROLE" ] && [ "$E2_ROLE" != "None" ] || { echo "cannot find the normalizer's role" >&2; return 1; }
  echo "$E2_ROLE"
}

e2_queue() {
  if [ -z "$E2_QUEUE" ]; then
    E2_QUEUE=$(e2_aws sqs get-queue-url --queue-name "$E2_QUEUE_NAME" --query QueueUrl --output text)
  fi
  echo "$E2_QUEUE"
}

e2depth() {
  e2_aws sqs get-queue-attributes --queue-url "$(e2_queue)" \
    --attribute-names ApproximateNumberOfMessages \
    --query 'Attributes.ApproximateNumberOfMessages' --output text
}

e2count() {
  # Flood findings are the only ones under account 000000000000.
  e2_aws dynamodb query --table-name cloudsentinel-findings --select COUNT \
    --key-condition-expression 'pk = :pk' \
    --expression-attribute-values '{":pk":{"S":"guardduty#000000000000"}}' \
    --query Count --output text
}

e2alarms() {
  e2_aws cloudwatch describe-alarms --alarm-names "${E2_ALARMS[@]}" \
    --query 'MetricAlarms[].[AlarmName,StateValue,StateUpdatedTimestamp]' --output text
}

e2chk() {
  echo "identity:"; e2_aws sts get-caller-identity --output text || return 1
  echo "role:     $(e2_role)" || return 1
  echo "queue:    $(e2_queue)  depth $(e2depth)"
  echo "flood findings in the table: $(e2count)"
  echo "alarms:"; e2alarms
  python -c "import boto3" 2>/dev/null || { echo "the venv is not active: python cannot import boto3" >&2; return 1; }
  local depth count
  depth=$(e2depth); count=$(e2count)
  if [ "$depth" != "0" ] || [ "$count" != "0" ]; then
    echo "not clean: queue depth $depth, flood findings $count — run e2cleanup first" >&2; return 1
  fi
  echo "preflight ok"
}

e2abort() {
  E2_ABORTED=1
  e2_say "removing the denial (abort)"
  e2_aws iam delete-role-policy --role-name "$(e2_role)" --policy-name "$E2_POLICY_NAME" \
    && e2_say "denial removed" || e2_say "delete-role-policy failed or the policy was already gone"
}

e2_sleep_until() {
  # Sleep in short steps until $1 seconds after $E2_T0, so Ctrl-C is honoured
  # within five seconds and the abort flag is seen.
  local target=$(( E2_T0 + $1 )) now
  while :; do
    [ -n "$E2_ABORTED" ] && return 1
    now=$(date -u +%s)
    [ "$now" -ge "$target" ] && return 0
    if [ $(( target - now )) -gt 5 ]; then sleep 5; else sleep $(( target - now )); fi
  done
}

e2wait() {
  # e2wait N S: until the flood count reaches N or S seconds pass.
  local want="$1" limit="${2:-1200}" start count
  start=$(date -u +%s)
  while :; do
    [ -n "$E2_ABORTED" ] && return 1
    count=$(e2count)
    e2_say "flood findings stored: $count of $want; queue depth $(e2depth)"
    [ "$count" -ge "$want" ] && return 0
    [ $(( $(date -u +%s) - start )) -ge "$limit" ] && { e2_say "gave up waiting after ${limit}s"; return 1; }
    sleep 30
  done
}

e2_wait_alarm() {
  # e2_wait_alarm NAME STATE S: until the alarm is in STATE or S seconds pass.
  local name="$1" want="$2" limit="${3:-900}" start state
  start=$(date -u +%s)
  while :; do
    [ -n "$E2_ABORTED" ] && return 1
    state=$(e2_aws cloudwatch describe-alarms --alarm-names "$name" --query 'MetricAlarms[0].StateValue' --output text)
    e2_say "$name is $state"
    [ "$state" = "$want" ] && return 0
    [ $(( $(date -u +%s) - start )) -ge "$limit" ] && { e2_say "$name not $want after ${limit}s"; return 1; }
    sleep 30
  done
}

e2run() {
  E2_ABORTED=
  E2_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  E2_LOG="$HOME/Downloads/e2-matched-$E2_STAMP.txt"
  local role; role=$(e2_role) || return 1
  trap 'e2abort' INT
  e2_say "E2 matched re-run: $E2_COUNT findings at $E2_RATE/s at +${E2_FLOOD_AT}s, denial removed at +${E2_DELETE_AT}s; role $role; log $E2_LOG"
  e2_say "before: queue depth $(e2depth), flood findings $(e2count)"
  e2alarms | tee -a "$E2_LOG"

  E2_T0=$(date -u +%s)
  e2_say "put-role-policy $E2_POLICY_NAME on $role (the denial)"
  e2_aws iam put-role-policy --role-name "$role" --policy-name "$E2_POLICY_NAME" --policy-document "$E2_DENY_DOC" \
    || { e2_say "put-role-policy failed; nothing to undo"; trap - INT; return 1; }

  e2_sleep_until "$E2_FLOOD_AT" || { trap - INT; return 1; }
  e2_say "flood: $E2_COUNT findings at $E2_RATE/s"
  python scripts/flood_findings.py --count "$E2_COUNT" --rate "$E2_RATE" --profile "$E2_PROFILE" 2>&1 | tee -a "$E2_LOG"

  e2_sleep_until "$E2_DELETE_AT" || { trap - INT; return 1; }
  e2_say "during the denial: queue depth $(e2depth), flood findings $(e2count)"
  e2alarms | tee -a "$E2_LOG"
  e2_say "delete-role-policy $E2_POLICY_NAME (the denial removed, +$(( $(date -u +%s) - E2_T0 ))s)"
  e2_aws iam delete-role-policy --role-name "$role" --policy-name "$E2_POLICY_NAME" \
    && e2_say "denial removed" || e2_say "delete-role-policy failed — run e2abort"
  trap - INT

  e2_say "waiting for the held findings to store (IAM propagation took about two minutes on 8 October)"
  e2wait "$E2_COUNT" 1200
  e2alarms | tee -a "$E2_LOG"
  e2_say "waiting for findings-fresh to return to OK"
  e2_wait_alarm cloudsentinel-slo-findings-fresh OK 1200
  e2_say "waiting for controls-unchanged to return to OK"
  e2_wait_alarm cloudsentinel-slo-controls-unchanged OK 900
  e2_say "after: queue depth $(e2depth), flood findings $(e2count)"
  e2alarms | tee -a "$E2_LOG"
  e2_say "done; now e2collect, then check the inbox against the histories, then e2cleanup"
}

e2collect() {
  [ -n "$E2_T0" ] || { echo "no run in this shell; set E2_T0 to the run's start epoch" >&2; return 1; }
  local out="$HOME/Downloads/e2-matched-${E2_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}-evidence.txt"
  local start end start_ms end_ms
  start=$(date -u -d "@$(( E2_T0 - 120 ))" +%Y-%m-%dT%H:%M:%SZ)
  end=$(date -u -d "@$(( $(date -u +%s) + 60 ))" +%Y-%m-%dT%H:%M:%SZ)
  start_ms=$(( (E2_T0 - 120) * 1000 )); end_ms=$(( ($(date -u +%s) + 60) * 1000 ))
  {
    echo "E2 matched re-run evidence, collected $(e2_now); run started $(date -u -d "@$E2_T0" +%Y-%m-%dT%H:%M:%SZ) by the sender's clock"
    echo; echo "== queue depth: $(e2depth); flood findings: $(e2count)"
    for a in "${E2_ALARMS[@]}"; do
      echo; echo "== alarm history: $a (UTC)"
      e2_aws cloudwatch describe-alarm-history --alarm-name "$a" --start-date "$start" --end-date "$end" \
        --query 'reverse(sort_by(AlarmHistoryItems,&Timestamp))[].[Timestamp,HistoryItemType,HistorySummary]' --output text
    done
    echo; echo "== control-change log ($E2_LOG_GROUP)"
    e2_aws logs filter-log-events --log-group-name "$E2_LOG_GROUP" --start-time "$start_ms" --end-time "$end_ms" \
      --query 'events[].[timestamp,message]' --output text
    echo; echo "== normalizer IteratorAge, maximum per minute (seconds)"
    e2_aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name IteratorAge \
      --dimensions Name=FunctionName,Value="$E2_FUNCTION" --statistics Maximum --period 60 \
      --start-time "$start" --end-time "$end" \
      --query 'sort_by(Datapoints,&Timestamp)[].[Timestamp,Maximum]' --output text | awk '{printf "%s %.1f\n", $1, $2/1000}'
    for m in RecordsReceived RecordsFailed RecordsRejected; do
      echo; echo "== normalizer $m, sum per minute"
      e2_aws cloudwatch get-metric-statistics --namespace CloudSentinel --metric-name "$m" \
        --dimensions Name=Component,Value=normalizer --statistics Sum --period 60 \
        --start-time "$start" --end-time "$end" \
        --query 'sort_by(Datapoints,&Timestamp)[].[Timestamp,Sum]' --output text
    done
    echo; echo "== normalizer log: rejections and the first and last failures"
    e2_aws logs filter-log-events --log-group-name "/aws/lambda/$E2_FUNCTION" --start-time "$start_ms" --end-time "$end_ms" \
      --filter-pattern '?"Rejected record" ?"Failed to process record"' \
      --query 'events[].[timestamp,message]' --output text | awk 'NR<=5 || /Rejected/ {print} {last=$0} END {print "..."; print last}'
    echo; echo "== latency of the flood findings (measure.py --since the run's start, a minute early)"
    python scripts/measure.py --since "$start" --profile "$E2_PROFILE"
  } 2>&1 | tee "$out"
  echo "written to $out"
}

e2cleanup() {
  e2_say "purging the failure queue and the flood findings"
  e2_aws sqs purge-queue --queue-url "$(e2_queue)"
  python scripts/flood_findings.py --purge --profile "$E2_PROFILE"
  echo "queue depth $(e2depth); flood findings $(e2count)"
}

normlat() {
  # Normal traffic since the E1 re-run's rollback on 12 October (20:06 UTC),
  # with the flood of E1's third run purged. The JSON is committed beside
  # docs/evaluation-e4.json; the row in docs/evaluation.md is filled from it.
  python scripts/measure.py --since 2026-10-12T20:10:00Z --profile "$E2_PROFILE" \
    --json docs/evaluation-normal.json | tee "$HOME/Downloads/normal-latency.txt"
}
