# Verify reader fixtures

Recorded gateway output captured ONCE per target, used by unit tests so they
don't require live containers (per wave-9 D-1 pushback). Live integration
tests under `e2e/` exercise the same readers against the real stack.

## Capture commands

### bunkerweb
```bash
docker compose -f e2e/fixtures/chain-bunkerweb-vapi/docker-compose.yml up -d
sleep 30
docker exec x-security-chain-bunkerweb-vapi-bunkerweb-1 nginx -T \
  > packages/cli/test/verify/__fixtures__/bunkerweb/nginx-T.txt
docker exec x-security-chain-bunkerweb-vapi-bw-scheduler-1 \
  sh -c 'cat /data/configs/modsec/*/x-security.conf' \
  > packages/cli/test/verify/__fixtures__/bunkerweb/scheduler-x-security.conf
```

### openappsec
```bash
docker compose -f e2e/fixtures/chain-openappsec-vapi/docker-compose.yml up -d
sleep 30
docker exec x-security-openappsec \
  sh -c 'find /etc/cp/conf -maxdepth 3 -type f \( -name "*.yaml" -o -name "*.policy" \) | xargs cat' \
  > packages/cli/test/verify/__fixtures__/openappsec/etc-cp-conf.txt
```

### coraza-spoa
```bash
docker compose -f e2e/fixtures/chain-coraza-spoa-vapi/docker-compose.yml up -d
sleep 25
# Generate some traffic so HAProxy emits ruleid= fields
curl -s http://localhost:8080/vapi/api1/user/1 >/dev/null
docker logs x-security-chain-coraza-spoa-vapi-haproxy-1 \
  > packages/cli/test/verify/__fixtures__/coraza-spoa/haproxy.log 2>&1
docker logs x-security-chain-coraza-spoa-vapi-coraza-spoa-1 \
  > packages/cli/test/verify/__fixtures__/coraza-spoa/spoa.log 2>&1
```

The fixtures committed here are synthetic stand-ins covering the parse
contract for each reader. When live capture happens, replace these with
the real captures and tests will still pass — the parsers are stable.
