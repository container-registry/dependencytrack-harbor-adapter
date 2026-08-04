const fs = require('fs')
const yaml = require('js-yaml')

module.exports = async ({ github, context, core }) => {
  const { owner, repo } = context.repo
  const settings = yaml.load(fs.readFileSync('.github/settings.yml', 'utf8'))
  const mode = process.env.INPUT_MODE || (context.eventName === 'schedule' ? 'check' : 'verify')
  core.info(`Mode: ${mode}`)

  // Apply repository settings
  async function applyRepository() {
    if (!settings.repository) return
    // repos.update (PATCH /repos/{owner}/{repo}) silently ignores `topics`;
    // they have their own replace-all endpoint. Splitting them here keeps a
    // configured topics list from permanently failing drift verification.
    const { topics, ...repoSettings } = settings.repository
    await github.rest.repos.update({ owner, repo, ...repoSettings })
    if (Array.isArray(topics)) {
      await github.rest.repos.replaceAllTopics({ owner, repo, names: topics })
    }
    core.info('✓ repository')
  }

  // Apply labels (create or update)
  async function applyLabels() {
    if (!settings.labels) return
    // paginate: past 100 labels a managed one on a later page would look
    // missing and createLabel would fail with already_exists.
    const existing = await github.paginate(github.rest.issues.listLabelsForRepo, { owner, repo, per_page: 100 })
    const existingNames = new Set(existing.map(l => l.name))
    for (const [name, config] of Object.entries(settings.labels)) {
      if (existingNames.has(name)) {
        await github.rest.issues.updateLabel({ owner, repo, name, ...config })
      } else {
        await github.rest.issues.createLabel({ owner, repo, name, ...config })
      }
    }
    core.info('✓ labels')
  }

  // Apply security settings
  async function applySecurity() {
    if (!settings.security) return
    await github.rest.repos.update({ owner, repo, security_and_analysis: settings.security })
    core.info('✓ security')
  }

  // Apply code scanning default setup
  async function applyCodeScanning() {
    if (!settings.code_scanning || settings.code_scanning.state !== 'configured') return
    await github.request('PATCH /repos/{owner}/{repo}/code-scanning/default-setup', {
      owner, repo, ...settings.code_scanning
    })
    core.info('✓ code_scanning')
  }

  // Apply rulesets (create or update)
  async function applyRulesets() {
    if (!settings.rulesets) return
    let existing = []
    try {
      const response = await github.rest.repos.getRepoRulesets({ owner, repo })
      existing = response.data
    } catch (e) {
      // No rulesets exist
    }
    const existingMap = Object.fromEntries(existing.map(r => [r.name, r.id]))
    for (const [name, config] of Object.entries(settings.rulesets)) {
      if (existingMap[name]) {
        await github.rest.repos.updateRepoRuleset({ owner, repo, ruleset_id: existingMap[name], name, ...config })
      } else {
        await github.rest.repos.createRepoRuleset({ owner, repo, name, ...config })
      }
    }
    core.info('✓ rulesets')
  }

  // Apply branch protection
  async function applyBranches() {
    if (!settings.branches) return
    for (const [branch, config] of Object.entries(settings.branches)) {
      if (config.protection) {
        await github.rest.repos.updateBranchProtection({ owner, repo, branch, ...config.protection })
      }
    }
    core.info('✓ branches')
  }

  // Apply environments
  async function applyEnvironments() {
    if (!settings.environments) return
    for (const [envName, config] of Object.entries(settings.environments)) {
      await github.rest.repos.createOrUpdateEnvironment({ owner, repo, environment_name: envName, ...config })
    }
    core.info('✓ environments')
  }

  // Apply all settings, collecting failures rather than swallowing them. An apply
  // run is deliberate, so a missing SETTINGS_TOKEN or a permission error has to
  // fail the step: warnings alone render a green check on a run that changed
  // nothing. Every section is still attempted so one failure does not hide the rest.
  async function applyAll() {
    const sections = [
      ['repository', applyRepository],
      ['labels', applyLabels],
      ['security', applySecurity],
      ['code_scanning', applyCodeScanning],
      ['rulesets', applyRulesets],
      ['branches', applyBranches],
      ['environments', applyEnvironments],
    ]
    const failures = []
    for (const [name, fn] of sections) {
      try {
        await fn()
      } catch (e) {
        // The PAT hint only fits the sections the default GITHUB_TOKEN cannot
        // write; blaming the token for a label typo or a rate limit misleads.
        const needsToken = ['repository', 'security', 'rulesets', 'branches', 'environments'].includes(name)
        core.warning(`${name}: ${e.message}${needsToken ? ' (needs SETTINGS_TOKEN?)' : ''}`)
        failures.push(name)
      }
    }
    if (failures.length) {
      throw new Error(`failed to apply: ${failures.join(', ')} (see warnings above; a PAT in SETTINGS_TOKEN is required for repository, security, rulesets, branches and environments)`)
    }
  }

  // Export current settings from GitHub
  async function exportSettings() {
    const { data: r } = await github.rest.repos.get({ owner, repo })
    const labels = await github.paginate(github.rest.issues.listLabelsForRepo, { owner, repo, per_page: 100 })

    let codeScanningData = {}
    try {
      const cs = await github.request('GET /repos/{owner}/{repo}/code-scanning/default-setup', { owner, repo })
      codeScanningData = cs.data
    } catch (e) {
      // Code scanning not configured
    }

    let rulesetsData = []
    try {
      const rs = await github.rest.repos.getRepoRulesets({ owner, repo })
      rulesetsData = rs.data
    } catch (e) {
      // No rulesets
    }

    let branchProtection = null
    try {
      const bp = await github.rest.repos.getBranchProtection({ owner, repo, branch: r.default_branch })
      branchProtection = bp.data
    } catch (e) {
      // No branch protection
    }

    let environmentsData = []
    try {
      const envs = await github.rest.repos.getAllEnvironments({ owner, repo })
      environmentsData = envs.data.environments || []
    } catch (e) {
      // No environments
    }

    const result = {
      repository: {
        description: r.description,
        homepage: r.homepage || '',
        topics: r.topics,
        visibility: r.visibility,
        has_issues: r.has_issues,
        has_projects: r.has_projects,
        has_wiki: r.has_wiki,
        has_downloads: r.has_downloads,
        has_discussions: r.has_discussions,
        is_template: r.is_template,
        default_branch: r.default_branch,
        allow_forking: r.allow_forking,
        allow_squash_merge: r.allow_squash_merge,
        allow_merge_commit: r.allow_merge_commit,
        allow_rebase_merge: r.allow_rebase_merge,
        delete_branch_on_merge: r.delete_branch_on_merge,
        allow_auto_merge: r.allow_auto_merge,
        allow_update_branch: r.allow_update_branch,
        squash_merge_commit_title: r.squash_merge_commit_title,
        squash_merge_commit_message: r.squash_merge_commit_message,
        merge_commit_title: r.merge_commit_title,
        merge_commit_message: r.merge_commit_message,
        web_commit_signoff_required: r.web_commit_signoff_required
      },
      labels: Object.fromEntries(labels.map(l => [l.name, { color: l.color, description: l.description || '' }])),
      security: r.security_and_analysis ? {
        secret_scanning: { status: r.security_and_analysis.secret_scanning?.status },
        secret_scanning_push_protection: { status: r.security_and_analysis.secret_scanning_push_protection?.status },
        dependabot_security_updates: { status: r.security_and_analysis.dependabot_security_updates?.status }
      } : undefined,
      code_scanning: codeScanningData.state ? {
        state: codeScanningData.state,
        query_suite: codeScanningData.query_suite,
        languages: codeScanningData.languages
      } : undefined
    }

    // Add rulesets if any exist
    if (rulesetsData.length > 0) {
      result.rulesets = Object.fromEntries(rulesetsData.map(rs => {
        const { id, node_id, source, created_at, updated_at, _links, current_user_can_bypass, name, ...rest } = rs
        return [name, rest]
      }))
    }

    // Add branch protection if configured
    if (branchProtection) {
      result.branches = {
        [r.default_branch]: {
          protection: {
            required_status_checks: branchProtection.required_status_checks ? {
              strict: branchProtection.required_status_checks.strict,
              contexts: branchProtection.required_status_checks.contexts
            } : null,
            enforce_admins: branchProtection.enforce_admins?.enabled,
            required_pull_request_reviews: branchProtection.required_pull_request_reviews ? {
              required_approving_review_count: branchProtection.required_pull_request_reviews.required_approving_review_count,
              dismiss_stale_reviews: branchProtection.required_pull_request_reviews.dismiss_stale_reviews,
              require_code_owner_reviews: branchProtection.required_pull_request_reviews.require_code_owner_reviews
            } : null,
            restrictions: null,
            required_linear_history: branchProtection.required_linear_history?.enabled,
            allow_force_pushes: branchProtection.allow_force_pushes?.enabled,
            allow_deletions: branchProtection.allow_deletions?.enabled
          }
        }
      }
    }

    // Add environments if any exist
    if (environmentsData.length > 0) {
      result.environments = Object.fromEntries(environmentsData.map(env => {
        const { id, node_id, created_at, updated_at, html_url, name, ...rest } = env
        // Filter out empty values
        const filtered = Object.fromEntries(Object.entries(rest).filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && v.length === 0)))
        return [name, filtered]
      }))
    }

    return result
  }

  // Remove nulls and empty objects recursively
  function normalize(obj) {
    if (obj === null || obj === undefined) return undefined
    if (Array.isArray(obj)) {
      const filtered = obj.map(normalize).filter(v => v !== undefined)
      return filtered.length > 0 ? filtered : undefined
    }
    if (typeof obj === 'object') {
      const result = {}
      for (const [key, value] of Object.entries(obj)) {
        const normalized = normalize(value)
        if (normalized !== undefined) {
          result[key] = normalized
        }
      }
      return Object.keys(result).length > 0 ? result : undefined
    }
    return obj
  }

  // Sort object keys recursively for stable comparison. Arrays of primitives
  // (topics, status-check contexts, languages) are set-like in the GitHub API
  // and come back in arbitrary order, so they are sorted too; arrays of objects
  // keep their order.
  function sortKeys(obj) {
    if (obj === null || obj === undefined) return obj
    if (Array.isArray(obj)) {
      const mapped = obj.map(sortKeys)
      return mapped.every(v => typeof v !== 'object' || v === null) ? [...mapped].sort() : mapped
    }
    if (typeof obj === 'object') {
      return Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = sortKeys(obj[key])
        return acc
      }, {})
    }
    return obj
  }

  // Detect drift between settings.yml and GitHub. With soft=true a mismatch is
  // reported without failing the step (used by the verify retry loop).
  async function detectDrift(soft = false) {
    core.info('Exporting current GitHub settings...')
    const current = await exportSettings()
    const expected = sortKeys(normalize(settings))
    const actual = sortKeys(normalize(current))

    const expectedJson = JSON.stringify(expected, null, 2)
    const actualJson = JSON.stringify(actual, null, 2)

    if (expectedJson === actualJson) {
      core.info('✓ No drift detected - settings.yml matches GitHub')
      return true
    }

    if (soft) {
      core.info('Drift (not yet failing): settings.yml differs from GitHub state.')
    } else {
      core.setFailed('Drift detected! settings.yml differs from GitHub state.')
      core.info('Expected:\n' + expectedJson)
      core.info('Actual:\n' + actualJson)
    }
    return false
  }

  // Main execution
  if (mode === 'check') {
    core.startGroup('Checking for drift')
    await detectDrift()
    core.endGroup()
  } else if (mode === 'apply') {
    core.startGroup('Applying settings')
    await applyAll()
    core.endGroup()
  } else { // verify
    core.startGroup('Applying settings')
    await applyAll()
    core.endGroup()
    core.startGroup('Verifying settings were applied')
    // GitHub applies some settings (security, branch protection, rulesets)
    // eventually, not synchronously; a fixed 2s sleep failed verification on
    // slow propagation. Poll with backoff instead, and only the last attempt
    // is allowed to record the failure.
    const delaysMs = [2000, 4000, 8000, 16000]
    for (let attempt = 0; attempt < delaysMs.length; attempt++) {
      await new Promise(r => setTimeout(r, delaysMs[attempt]))
      const lastAttempt = attempt === delaysMs.length - 1
      if (await detectDrift(!lastAttempt)) break
      if (!lastAttempt) core.info(`Drift still visible; retrying (${attempt + 1}/${delaysMs.length})`)
    }
    core.endGroup()
  }
}
